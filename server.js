import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

const { Pool } = pg;

const app = express();

const PORT = Number(process.env.PORT || 10000);

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;


/* =========================================
   BASIC CONFIG
========================================= */

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing.");
}


/* =========================================
   DATABASE
========================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    DATABASE_URL &&
    !DATABASE_URL.includes("localhost")
      ? { rejectUnauthorized: false }
      : false
});

const q = (text, params = []) =>
  pool.query(text, params);


/* =========================================
   MIDDLEWARE
========================================= */

app.use(
  cors({
    origin: true,
    credentials: false
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);


/* =========================================
   JWT
========================================= */

function tokenFor(user) {

  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured");
  }

  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}


/* =========================================
   AUTH MIDDLEWARE
========================================= */

function auth(req, res, next) {

  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  const token =
    header.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  try {

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();

  } catch (error) {

    return res.status(401).json({
      error: "Invalid or expired login"
    });

  }
}


/* =========================================
   ROLE MIDDLEWARE
========================================= */

function role(...allowedRoles) {

  return (req, res, next) => {

    const userRole =
      String(req.user?.role || "")
        .toLowerCase();

    if (allowedRoles.includes(userRole)) {
      return next();
    }

    return res.status(403).json({
      error: "Permission denied"
    });

  };

}


/* =========================================
   DATABASE INIT
========================================= */

async function init() {

  if (!DATABASE_URL) {
    throw new Error(
      "DATABASE_URL is required"
    );
  }

  if (!JWT_SECRET) {
    throw new Error(
      "JWT_SECRET is required"
    );
  }


  /* =======================================
     USERS
  ======================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS users (

      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      email TEXT NOT NULL UNIQUE,

      password TEXT NOT NULL,

      role TEXT NOT NULL DEFAULT 'customer'

        CHECK (
          role IN (
            'customer',
            'seller',
            'admin'
          )
        ),

      created_at
        TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);


  /* =======================================
     SELLER DETAILS
     Safe for existing database
  ======================================= */

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS business_name TEXT
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS gst_number VARCHAR(15)
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mobile VARCHAR(20)
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS address TEXT
  `);


  /* =======================================
     UNIQUE GST
  ======================================= */

  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    idx_users_gst_unique
    ON users(gst_number)
    WHERE gst_number IS NOT NULL
  `);


  /* =======================================
     PRODUCTS
  ======================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS products (

      id SERIAL PRIMARY KEY,

      seller_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      name TEXT NOT NULL,

      description TEXT NOT NULL
        DEFAULT '',

      price NUMERIC(12,2) NOT NULL
        DEFAULT 0,

      stock INTEGER NOT NULL
        DEFAULT 0,

      image TEXT NOT NULL
        DEFAULT '',

      active BOOLEAN NOT NULL
        DEFAULT TRUE,

      created_at
        TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_products_seller
    ON products(seller_id)
  `);


  /* =======================================
     ORDERS
  ======================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS orders (

      id SERIAL PRIMARY KEY,

      customer_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      total NUMERIC(12,2) NOT NULL
        DEFAULT 0,

      status TEXT NOT NULL
        DEFAULT 'pending'

        CHECK (
          status IN (
            'pending',
            'confirmed',
            'shipped',
            'delivered',
            'cancelled'
          )
        ),

      created_at
        TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);


  /* =======================================
     ORDER ITEMS
  ======================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS order_items (

      id SERIAL PRIMARY KEY,

      order_id INTEGER NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,

      product_id INTEGER NOT NULL
        REFERENCES products(id)
        ON DELETE RESTRICT,

      seller_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE RESTRICT,

      product_name TEXT NOT NULL,

      price NUMERIC(12,2) NOT NULL,

      quantity INTEGER NOT NULL,

      subtotal NUMERIC(12,2) NOT NULL
    )
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_customer
    ON orders(customer_id)
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_order_items_seller
    ON order_items(seller_id)
  `);


  /* =======================================
     ADMIN ACCOUNT
  ======================================= */

  const adminEmail =
    String(
      process.env.ADMIN_EMAIL ||
      "admin@shipnova.local"
    )
      .trim()
      .toLowerCase();


  const adminPassword =
    String(
      process.env.ADMIN_PASSWORD || ""
    );


  if (!adminPassword) {

    console.warn(
      "ADMIN_PASSWORD is not set. " +
      "Admin account was not created/updated."
    );

  } else {

    const hash =
      await bcrypt.hash(
        adminPassword,
        12
      );


    await q(
      `
      INSERT INTO users(
        name,
        email,
        password,
        role
      )

      VALUES(
        $1,
        $2,
        $3,
        'admin'
      )

      ON CONFLICT(email)

      DO UPDATE SET

        name = EXCLUDED.name,

        password = EXCLUDED.password,

        role = 'admin'
      `,
      [
        "Administrator",
        adminEmail,
        hash
      ]
    );


    console.log(
      `Admin account ready: ${adminEmail}`
    );

  }

}


/* =========================================
   BASIC ROUTES
========================================= */

app.get("/", (req, res) => {

  res.json({
    ok: true,
    name: "ShipNova API",
    version: "5.0"
  });

});


app.get(
  "/api/health",
  async (req, res) => {

    try {

      await q("SELECT 1");

      res.json({
        ok: true,
        database: "connected"
      });

    } catch (error) {

      console.error(error);

      res.status(503).json({
        ok: false,
        database: "unavailable"
      });

    }

  }
);


/* =========================================
   REGISTER
   CUSTOMER + SELLER
========================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const {
        name,
        email,
        password,
        role: requestedRole = "customer",

        businessName,
        gstNumber,
        mobile,
        address

      } = req.body || {};


      if (!name || !email || !password) {

        return res.status(400).json({
          error:
            "name, email and password are required"
        });

      }


      const cleanRole =
        String(requestedRole)
          .trim()
          .toLowerCase();


      /*
       * Admin registration is never
       * allowed from public API.
       */

      if (
        !["customer", "seller"]
          .includes(cleanRole)
      ) {

        return res.status(400).json({
          error: "Invalid role"
        });

      }


      const cleanName =
        String(name).trim();


      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();


      const cleanPassword =
        String(password);


      if (cleanName.length < 2) {

        return res.status(400).json({
          error:
            "Name must contain at least 2 characters"
        });

      }


      if (cleanPassword.length < 6) {

        return res.status(400).json({
          error:
            "Password must contain at least 6 characters"
        });

      }


      /* =====================================
         SELLER DATA
      ===================================== */

      let cleanBusinessName = null;
      let cleanGstNumber = null;
      let cleanMobile = null;
      let cleanAddress = null;


      if (cleanRole === "seller") {

        cleanBusinessName =
          String(
            businessName || ""
          ).trim();


        cleanGstNumber =
          String(
            gstNumber || ""
          )
            .trim()
            .toUpperCase();


        cleanMobile =
          String(
            mobile || ""
          )
            .replace(/\D/g, "");


        cleanAddress =
          String(
            address || ""
          ).trim();


        if (!cleanBusinessName) {

          return res.status(400).json({
            error:
              "Business Name is required"
          });

        }


        /*
         * GSTIN format validation.
         *
         * This checks format only.
         * It does NOT verify GST against
         * the government GST portal.
         */

        const gstRegex =
          /^[0-9]{2}[A-Z]{5}[0-9]{