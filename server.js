#!/usr/bin/env node

process.title = "videoconf-server";

const bcrypt = require("bcrypt");
const config = require("./config/config");
require("./db/lib/server");
const User = require("./db/models/user");
const fs = require("fs");
const http = require("http");
const spdy = require("spdy");
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const compression = require("compression");
const mediasoup = require("mediasoup");
const AwaitQueue = require("awaitqueue");
const Logger = require("./lib/Logger");
const Room = require("./lib/Room");
const Peer = require("./lib/Peer");
const base64 = require("base-64");
const helmet = require("helmet");
const userRoles = require("./userRoles");
const { loginHelper, logoutHelper } = require("./httpHelper");
// auth
const passport = require("passport");
const LTIStrategy = require("passport-lti");
const imsLti = require("ims-lti");
const SAMLStrategy = require("passport-saml").Strategy;
const LocalStrategy = require("passport-local").Strategy;
const redis = require("redis");
const redisClient = redis.createClient(config.redisOptions);
const { Issuer, Strategy } = require("openid-client");
const expressSession = require("express-session");
const RedisStore = require("connect-redis")(expressSession);
const sharedSession = require("express-socket.io-session");
const interactiveServer = require("./lib/interactiveServer");
const promExporter = require("./lib/promExporter");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const Meeting = require("./db/models/meeting");

/* eslint-disable no-console */
process.env.DEBUG = "*";
console.log("- process.env.DEBUG:", process.env.DEBUG);
console.log(
  "- config.mediasoup.worker.logLevel:",
  config.mediasoup.worker.logLevel
);
console.log(
  "- config.mediasoup.worker.logTags:",
  config.mediasoup.worker.logTags
);
/* eslint-enable no-console */

const logger = new Logger();

const queue = new AwaitQueue();

let statusLogger = null;

if ("StatusLogger" in config) statusLogger = new config.StatusLogger();

// mediasoup Workers.
// @type {Array<mediasoup.Worker>}
const mediasoupWorkers = [];

// Map of Room instances indexed by roomId.
const rooms = new Map();

// Map of Peer instances indexed by peerId.
const peers = new Map();

// TLS server configuration.
const tls = {
  cert: fs.readFileSync(config.tls.cert),
  key: fs.readFileSync(config.tls.key),
  secureOptions: "tlsv12",
  ciphers: [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
  ].join(":"),
  honorCipherOrder: true,
};

const app = express();

app.use(helmet.hsts());
const sharedCookieParser = cookieParser();

app.use(sharedCookieParser);
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ limit: "5mb", extended: true }));
app.use(cors());

const session = expressSession({
  secret: config.cookieSecret,
  name: config.cookieName,
  resave: true,
  saveUninitialized: true,
  store: new RedisStore({ client: redisClient }),
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 60 * 60 * 1000,
  },
});

if (config.trustProxy) {
  app.set("trust proxy", config.trustProxy);
}

app.use(session);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

let mainListener;
let io;

async function run() {
  try {
    // Open the interactive server.
    logger.warn("Before interactiveServer");
    await interactiveServer(rooms, peers);

    // start Prometheus exporter
    if (config.prometheus) {
      await promExporter(rooms, peers, config.prometheus);
    }

    logger.warn("Auth is not configured properly!");
    await setupAuth();

    logger.warn("Before runMediasoupWorkers");

    // Run a mediasoup Worker.
    await runMediasoupWorkers();

    // Run HTTPS server.
    await runHttpsServer();

    logger.warn("Before runWebSocketServer");
    // Run WebSocketServer.
    await runWebSocketServer();

    // eslint-disable-next-line no-unused-vars
    const errorHandler = (err, req, res, next) => {
      const trackingId = uuidv4();

      res.status(500).send(
        `<h1>Internal Server Error</h1>
				<p>If you report this error, please also report this 
				<i>tracking ID</i> which makes it possible to locate your session
				in the logs which are available to the system administrator: 
				<b>${trackingId}</b></p>`
      );
      logger.error(
        "Express error handler dump with tracking ID: %s, error dump: %o",
        trackingId,
        err
      );
    };

    // eslint-disable-next-line no-unused-vars
    app.use(errorHandler);
  } catch (error) {
    logger.error('run() [error:"%o"]', error);
  }
}

function statusLog() {
  if (statusLogger) {
    statusLogger.log({
      rooms: rooms,
      peers: peers,
    });
  }
}

async function setupAuth() {
  app.use("/user", require("./db/routes/user"));
  app.use("/meeting", require("./db/routes/meeting"));
  app.use("/group", require("./db/routes/group"));

  // app.post("/auth/signin", async (req, res) => {
  //   if (req.body.username && req.body.password) {
  //     var username = req.body.username;
  //     var password = req.body.password;
  //     await User.findOne({ username })
  //       .then((details) => {
  //         if (details && details.password == password) {
  //           req.session.user = details;
  //           res.send({
  //             data: details,
  //             status: 200,
  //             message: "Login Successfull",
  //           });
  //         } else {
  //           res.send({ data: [], status: 401, message: "Invalid Password" });
  //         }
  //       })
  //       .catch((err) => res.send({ data: [], status: 401, message: err }));
  //   } else {
  //     res.send({ data: [], status: 401, message: "Invalid Credentials" });
  //   }
  // });

  // app.post("/auth/signup", async (req, res) => {
  //   if (req.body.username && req.body.password) {
  //     await User.init();
  //     var username = req.body.username;
  //     var password = req.body.password;
  //     await User.create({ username: username, password: password })
  //       .then((details) => {
  //         req.session.user = details;
  //         res.send({
  //           data: details,
  //           status: 200,
  //           message: "Signup Successfull",
  //         });
  //       })
  //       .catch((err) =>
  //         res.send({ data: [], status: 401, message: err.message })
  //       );
  //   } else {
  //     res.send({ data: [], status: 401, message: "Invalid Credentials" });
  //   }
  // });

  // app.get("/auth/logout", (req, res) => {
  //   const { peerId } = req.session;

  //   const peer = peers.get(peerId);

  //   if (peer) {
  //     for (const role of peer.roles) {
  //       if (role.id !== userRoles.NORMAL.id) peer.removeRole(role);
  //     }
  //   }

  //   req.logout();
  //   req.session.destroy(() => res.send(logoutHelper()));
  // });
}

async function runHttpsServer() {
  app.use(compression());

  app.use(
    "/.well-known/acme-challenge",
    express.static("public/.well-known/acme-challenge")
  );

  app.all("*", async (req, res, next) => {
    if (req.secure || config.httpOnly) {
      let ltiURL;

      try {
        ltiURL = new URL(
          `${req.protocol}://${req.get("host")}${req.originalUrl}`
        );
      } catch (error) {
        logger.error("Error parsing LTI url: %o", error);
      }

      if (
        req.isAuthenticated &&
        req.user &&
        req.user.displayName &&
        !ltiURL.searchParams.get("displayName") &&
        !isPathAlreadyTaken(req.url)
      ) {
        ltiURL.searchParams.append("displayName", req.user.displayName);

        res.redirect(ltiURL);
      } else {
        const specialChars = "<>@!^*()[]{}:;|'\"\\,~`";

        for (let i = 0; i < specialChars.length; i++) {
          if (req.url.substring(1).indexOf(specialChars[i]) > -1) {
            req.url = `/${encodeURIComponent(encodeURI(req.url.substring(1)))}`;
            res.redirect(`${req.url}`);
          }
        }

        return next();
      }
    } else res.redirect(`https://${req.hostname}${req.url}`);
  });

  // Serve all files in the public folder as static files.
  app.use(express.static("public"));

  app.use((req, res) => res.sendFile(`${__dirname}/public/index.html`));

  if (config.httpOnly === true) {
    // http
    mainListener = http.createServer(app);
  } else {
    // https
    mainListener = spdy.createServer(tls, app);

    // http
    const redirectListener = http.createServer(app);

    if (config.listeningHost)
      redirectListener.listen(
        config.listeningRedirectPort,
        config.listeningHost
      );
    else redirectListener.listen(config.listeningRedirectPort);
  }

  // https or http
  if (config.listeningHost)
    mainListener.listen(config.listeningPort, config.listeningHost);
  else mainListener.listen(config.listeningPort);
}

function isPathAlreadyTaken(actualUrl) {
  const alreadyTakenPath = [
    "/config/",
    "/static/",
    "/images/",
    "/sounds/",
    "/favicon.",
    "/auth/",
  ];

  alreadyTakenPath.forEach((path) => {
    if (actualUrl.toString().startsWith(path)) return true;
  });

  return false;
}

/**
 * Create a WebSocketServer to allow WebSocket connections from browsers.
 */
async function runWebSocketServer() {
  io = require("socket.io")(mainListener, { cookie: false });

  io.use(sharedSession(session, sharedCookieParser, { autoSave: true }));

  // Handle connections from clients.
  io.on("connection", async (socket) => {
    const { roomId, peerId } = socket.handshake.query;
    if (!roomId || !peerId) {
      logger.warn("connection request without roomId and/or peerId");

      socket.disconnect(true);

      return;
    }
    // await Meeting.init();
    // await Meeting.create({ title: "abc", peerId, roomId: "abc" });

    logger.info(
      'connection request [roomId:"%s", peerId:"%s"]',
      roomId,
      peerId
    );

    queue
      .push(async () => {
        const { token } = socket.handshake.session;

        const room = await getOrCreateRoom({ roomId });

        let peer = peers.get(peerId);
        let returning = false;
        console.log("after peers", peerId, token);
        if (peer && !token) {
          console.log("hijacking sessions");
          // Don't allow hijacking sessions
          socket.disconnect(true);

          return;
        } else if (token && room.verifyPeer({ id: peerId, token })) {
          // Returning user, remove if old peer exists
          console.log("Returning user");
          if (peer) peer.close();

          returning = true;
        }

        peer = new Peer({ id: peerId, roomId, socket });

        peers.set(peerId, peer);

        peer.on("close", () => {
          peers.delete(peerId);

          statusLog();
        });

        if (
          Boolean(socket.handshake.session.passport) &&
          Boolean(socket.handshake.session.passport.user)
        ) {
          const {
            id,
            displayName,
            picture,
            email,
            _userinfo,
          } = socket.handshake.session.passport.user;

          peer.authId = id;
          peer.displayName = displayName;
          peer.picture = picture;
          peer.email = email;
          peer.authenticated = true;

          if (typeof config.userMapping === "function") {
            await config.userMapping({
              peer,
              room,
              roomId,
              userinfo: _userinfo,
            });
          }
        }

        room.handlePeer({ peer, returning });

        statusLog();
      })
      .catch((error) => {
        console.log("error", error);

        logger.error(
          'room creation or room joining failed [error:"%o"]',
          error
        );

        if (socket) socket.disconnect(true);

        return;
      });
  });
}

/**
 * Launch as many mediasoup Workers as given in the configuration file.
 */
async function runMediasoupWorkers() {
  const { numWorkers } = config.mediasoup;

  logger.info("running %d mediasoup Workers...", numWorkers);

  for (let i = 0; i < numWorkers; ++i) {
    const worker = await mediasoup.createWorker(config.mediasoup.worker);

    worker.on("died", () => {
      logger.error(
        "mediasoup Worker died, exiting  in 2 seconds... [pid:%d]",
        worker.pid
      );

      setTimeout(() => process.exit(1), 2000);
    });

    mediasoupWorkers.push(worker);
  }
}

/**
 * Get a Room instance (or create one if it does not exist).
 */
async function getOrCreateRoom({ roomId }) {
  console.log("I am here :: roomID", roomId);
  let room = rooms.get(roomId);

  // If the Room does not exist create a new one.
  if (!room) {
    console.log('creating a new Room [roomId:"%s"]', roomId);

    logger.info('creating a new Room [roomId:"%s"]', roomId);

    //const mediasoupWorker = getMediasoupWorker();

    room = await Room.create({ mediasoupWorkers, roomId, peers });

    rooms.set(roomId, room);

    statusLog();

    room.on("close", () => {
      rooms.delete(roomId);

      statusLog();
    });
  }

  return room;
}

run();
