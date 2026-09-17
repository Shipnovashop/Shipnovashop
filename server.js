// ============================================================
// ShipNovaShop API - Version 6.0
// Express + PostgreSQL + JWT + Razorpay + GST + Invoice
// Optional Shiprocket Courier Integration
// ============================================================

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");
const Razorpay = require("razorpay");

const app = express();
const PORT = process.env.PORT || 10000;

// ------------------------------------------------------------
// ENV
// ------------------------------------------------------------

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing");
  process.exit(1);
}

// ------------------------------------------------------------
// BUSINESS / SHIPPING / GST CONFIG
// ------------------------------------------------------------

const FREE_SHIPPING_THRESHOLD = Number(
  process.env.FREE_SHIPPING_THRESHOLD || 999
);

const SHIPPING_FEE = Number(process.env.SHIPPING_FEE || 59);

const DELIVERY_MIN_DAYS = Number(
  process.env.DELIVERY_MIN_DAYS || 3
);

const DELIVERY_MAX_DAYS = Number(
  process.env.DELIVERY_MAX_DAYS || 7
);

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || ""
).trim().toLowerCase();

const ADMIN_PASSWORD = String(
  process.env.ADMIN_PASSWORD || ""
);

const RAZORPAY_KEY_ID = String(
  process.env.RAZORPAY_KEY_ID || ""
).trim();

const RAZORPAY_KEY_SECRET = String(
  process.env.RAZORPAY_KEY_SECRET || ""
).trim();

const razorpay =
  RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: RAZORPAY_KEY_ID,
        key_secret: RAZORPAY_KEY_SECRET
      })
    : null;

// GST / Invoice

const BUSINESS_NAME = String(
  process.env.BUSINESS_NAME || "ShipNovaShop"
).trim();

const BUSINESS_GSTIN = String(
  process.env.BUSINESS_GSTIN || ""
).trim().toUpperCase();

const BUSINESS_STATE = String(
  process.env.BUSINESS_STATE || ""
).trim();

const BUSINESS_STATE_CODE = String(
  process.env.BUSINESS_STATE_CODE || ""
).trim();

const BUSINESS_ADDRESS = String(
  process.env.BUSINESS_ADDRESS || ""
).trim();

const BUSINESS_CITY = String(
  process.env.BUSINESS_CITY || ""
).trim();

const BUSINESS_PINCODE = String(
  process.env.BUSINESS_PINCODE || ""
).trim();

const INVOICE_PREFIX = String(
  process.env.INVOICE_PREFIX || "SN"
).trim();

const SHIPPING_GST_RATE = Number(
  process.env.SHIPPING_GST_RATE || 0
);

const PRICES_INCLUDE_GST =
  String(process.env.PRICES_INCLUDE_GST || "true").toLowerCase() !==
  "false";

// ------------------------------------------------------------
// SHIPROCKET CONFIG
// ------------------------------------------------------------

const SHIPROCKET_EMAIL = String(
  process.env.SHIPROCKET_EMAIL || ""
).trim();

const SHIPROCKET_PASSWORD = String(
  process.env.SHIPROCKET_PASSWORD || ""
);

const SHIPROCKET_PICKUP_LOCATION = String(
  process.env.SHIPROCKET_PICKUP_LOCATION || ""
).trim();

const SHIPROCKET_API_BASE = String(
  process.env.SHIPROCKET_API_BASE ||
    "https://apiv2.shiprocket.in/v1/external"
)
  .replace(/\/+$/, "");

const SHIPROCKET_DEFAULT_LENGTH = Number(
  process.env.SHIPROCKET_DEFAULT_LENGTH || 10
);

const SHIPROCKET_DEFAULT_BREADTH = Number(
  process.env.SHIPROCKET_DEFAULT_BREADTH || 10
);

const SHIPROCKET_DEFAULT_HEIGHT = Number(
  process.env.SHIPROCKET_DEFAULT_HEIGHT || 10
);

const SHIPROCKET_DEFAULT_WEIGHT = Number(
  process.env.SHIPROCKET_DEFAULT_WEIGHT || 0.5
);

const COURIER_PROVIDER = String(
  process.env.COURIER_PROVIDER || "shiprocket"
)
  .trim()
  .toLowerCase();

// ------------------------------------------------------------
// DATABASE
// ------------------------------------------------------------

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    DATABASE_URL && DATABASE_URL.includes("localhost")
      ? false
      : { rejectUnauthorized: false }
});

// ------------------------------------------------------------
// EXPRESS
// ------------------------------------------------------------

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(
  express.json({
    limit: "2mb"
  })
);

// ------------------------------------------------------------
// BASIC ROUTES
// ------------------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "ShipNova API",
    version: "6.0",
    message: "API is running"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "ShipNova API",
    version: "6.0",
    message: "API is running"
  });
});

// ------------------------------------------------------------
// HELPERS
// ------------------------------------------------------------

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const token = header.substring(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch (err) {
    return res.status(401).json({
      error: "Invalid or expired login"
    });
  }
}

function role(...roles) {
  return (req, res, next) => {
    if (
      !req.user ||
      !roles.includes(req.user.role)
    ) {
      return res.status(403).json({
        error: "Access denied"
      });
    }

    next();
  };
}

function money(value) {
  return Number(
    Number(value || 0).toFixed(2)
  );
}

function clean(value) {
  return String(value ?? "").trim();
}

function shippingFor(subtotal) {
  return subtotal >= FREE_SHIPPING_THRESHOLD
    ? 0
    : SHIPPING_FEE;
}

function gstFromInclusive(amount, rate) {
  const a = money(amount);
  const r = Number(rate || 0);

  if (!r) {
    return {
      taxable: a,
      gst: 0
    };
  }

  const taxable = money(
    a / (1 + r / 100)
  );

  const gst = money(
    a - taxable
  );

  return {
    taxable,
    gst
  };
}

function gstFromExclusive(amount, rate) {
  const a = money(amount);
  const r = Number(rate || 0);

  const gst = money(
    a * r / 100
  );

  return {
    taxable: a,
    gst
  };
}

function invoiceNumberFor(orderId) {
  return `${INVOICE_PREFIX}-${new Date().getFullYear()}-${String(
    orderId
  ).padStart(6, "0")}`;
}

function sameState(businessState, buyerState) {
  if (!businessState || !buyerState) {
    return false;
  }

  return (
    businessState.trim().toLowerCase() ===
    buyerState.trim().toLowerCase()
  );
}

function splitGST(gst, buyerState) {
  const total = money(gst);

  if (
    BUSINESS_STATE &&
    buyerState &&
    sameState(BUSINESS_STATE, buyerState)
  ) {
    return {
      cgst: money(total / 2),
      sgst: money(total - money(total / 2)),
      igst: 0
    };
  }

  if (BUSINESS_STATE && buyerState) {
    return {
      cgst: 0,
      sgst: 0,
      igst: total
    };
  }

  return {
    cgst: 0,
    sgst: 0,
    igst: 0
  };
}

function htmlEscape(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ------------------------------------------------------------
// SHIPROCKET
// ------------------------------------------------------------

let shiprocketToken = null;
let shiprocketTokenExpiresAt = 0;

async function getShiprocketToken() {
  if (
    !SHIPROCKET_EMAIL ||
    !SHIPROCKET_PASSWORD
  ) {
    throw new Error(
      "Shiprocket credentials not configured"
    );
  }

  if (
    shiprocketToken &&
    Date.now() < shiprocketTokenExpiresAt
  ) {
    return shiprocketToken;
  }

  const response = await fetch(
    `${SHIPROCKET_API_BASE}/auth/login`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email: SHIPROCKET_EMAIL,
        password: SHIPROCKET_PASSWORD
      })
    }
  );

  const data =
    await response.json().catch(() => ({}));

  if (
    !response.ok ||
    !data.token
  ) {
    throw new Error(
      data.message ||
        "Shiprocket login failed"
    );
  }

  shiprocketToken = data.token;

  shiprocketTokenExpiresAt =
    Date.now() +
    9 * 24 * 60 * 60 * 1000;

  return shiprocketToken;
}

async function shiprocketRequest(
  path,
  options = {},
  retry = true
) {
  const token =
    await getShiprocketToken();

  const response = await fetch(
    `${SHIPROCKET_API_BASE}${path}`,
    {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`
      }
    }
  );

  if (
    response.status === 401 &&
    retry
  ) {
    shiprocketToken = null;
    shiprocketTokenExpiresAt = 0;

    return shiprocketRequest(
      path,
      options,
      false
    );
  }

  const data =
    await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.message ||
        data.error ||
        `Shiprocket request failed (${response.status})`
    );
  }

  return data;
}

// ------------------------------------------------------------
// DATABASE INIT
// ------------------------------------------------------------

async function initDB() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'customer',
        approved BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        seller_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        price NUMERIC(12,2) NOT NULL DEFAULT 0,
        mrp NUMERIC(12,2) DEFAULT 0,
        stock INTEGER DEFAULT 0,
        brand TEXT DEFAULT '',
        sku TEXT DEFAULT '',
        category TEXT DEFAULT '',
        images JSONB DEFAULT '[]'::jsonb,
        weight NUMERIC(10,3) DEFAULT 0,
        size TEXT DEFAULT '',
        color TEXT DEFAULT '',
        low_stock_threshold INTEGER DEFAULT 5,
        approval_status TEXT DEFAULT 'approved',
        gst_rate NUMERIC(5,2) DEFAULT 0,
        hsn_code TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS addresses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        full_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        address_line1 TEXT NOT NULL,
        address_line2 TEXT DEFAULT '',
        landmark TEXT DEFAULT '',
        city TEXT NOT NULL,
        state TEXT NOT NULL,
        pincode TEXT NOT NULL,
        gstin TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        address_id INTEGER REFERENCES addresses(id) ON DELETE SET NULL,
        subtotal NUMERIC(12,2) DEFAULT 0,
        shipping_fee NUMERIC(12,2) DEFAULT 0,
        total NUMERIC(12,2) DEFAULT 0,
        payment_method TEXT DEFAULT 'COD',
        payment_status TEXT DEFAULT 'pending',
        status TEXT DEFAULT 'pending',
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        tracking_number TEXT,
        delivery_min_days INTEGER DEFAULT 3,
        delivery_max_days INTEGER DEFAULT 7,

        invoice_number TEXT,
        invoice_date TIMESTAMPTZ,
        billing_gstin TEXT DEFAULT '',
        seller_gstin TEXT DEFAULT '',
        gst_amount NUMERIC(12,2) DEFAULT 0,
        cgst_amount NUMERIC(12,2) DEFAULT 0,
        sgst_amount NUMERIC(12,2) DEFAULT 0,
        igst_amount NUMERIC(12,2) DEFAULT 0,
        taxable_amount NUMERIC(12,2) DEFAULT 0,
        shipping_taxable_amount NUMERIC(12,2) DEFAULT 0,
        shipping_gst_amount NUMERIC(12,2) DEFAULT 0,

        courier_provider TEXT DEFAULT '',
        shipment_id TEXT DEFAULT '',
        awb_number TEXT DEFAULT '',
        courier_status TEXT DEFAULT '',
        label_url TEXT DEFAULT '',
        pickup_scheduled_at TIMESTAMPTZ,
        shipped_at TIMESTAMPTZ,
        delivered_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
        product_id INTEGER,
        seller_id INTEGER,
        product_name TEXT,
        price NUMERIC(12,2) DEFAULT 0,
        quantity INTEGER DEFAULT 1,
        seller_status TEXT DEFAULT 'pending',
        seller_tracking_number TEXT DEFAULT '',
        seller_updated_at TIMESTAMPTZ,
        seller_shipped_at TIMESTAMPTZ,

        gst_rate NUMERIC(5,2) DEFAULT 0,
        hsn_code TEXT DEFAULT '',
        taxable_amount NUMERIC(12,2) DEFAULT 0,
        gst_amount NUMERIC(12,2) DEFAULT 0,
        cgst_amount NUMERIC(12,2) DEFAULT 0,
        sgst_amount NUMERIC(12,2) DEFAULT 0,
        igst_amount NUMERIC(12,2) DEFAULT 0
      )
    `);

    // --------------------------------------------------------
    // SAFE MIGRATIONS
    // --------------------------------------------------------

    const migrations = [

      // USERS
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT TRUE`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'customer'`,

      // PRODUCTS
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]'::jsonb`,
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS low_stock_threshold INTEGER DEFAULT 5`,
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'approved'`,
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS gst_rate NUMERIC(5,2) DEFAULT 0`,
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS hsn_code TEXT DEFAULT ''`,
      `ALTER TABLE products ADD COLUMN IF NOT EXISTS weight NUMERIC(10,3) DEFAULT 0`,

      // ADDRESSES
      `ALTER TABLE addresses ADD COLUMN IF NOT EXISTS gstin TEXT DEFAULT ''`,

      // ORDERS
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'pending'`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending'`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_number TEXT`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_min_days INTEGER DEFAULT 3`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_max_days INTEGER DEFAULT 7`,

      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_number TEXT`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_date TIMESTAMPTZ`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS billing_gstin TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS seller_gstin TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS gst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS cgst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS sgst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS igst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS taxable_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_taxable_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_gst_amount NUMERIC(12,2) DEFAULT 0`,

      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_provider TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipment_id TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS awb_number TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_status TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS label_url TEXT DEFAULT ''`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS pickup_scheduled_at TIMESTAMPTZ`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipped_at TIMESTAMPTZ`,
      `ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ`,

      // ORDER ITEMS
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS seller_status TEXT DEFAULT 'pending'`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS seller_tracking_number TEXT DEFAULT ''`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS seller_updated_at TIMESTAMPTZ`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS seller_shipped_at TIMESTAMPTZ`,

      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS gst_rate NUMERIC(5,2) DEFAULT 0`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS hsn_code TEXT DEFAULT ''`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS taxable_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS gst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS cgst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS sgst_amount NUMERIC(12,2) DEFAULT 0`,
      `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS igst_amount NUMERIC(12,2) DEFAULT 0`
    ];

    for (const sql of migrations) {
      await client.query(sql);
    }

    // Defaults

    await client.query(`
      UPDATE users
      SET approved = TRUE
      WHERE approved IS NULL
    `);

    await client.query(`
      UPDATE products
      SET approval_status = 'approved'
      WHERE approval_status IS NULL
         OR TRIM(approval_status) = ''
    `);

    await client.query(`
      UPDATE products
      SET images = '[]'::jsonb
      WHERE images IS NULL
    `);

    await client.query(`
      UPDATE products
      SET low_stock_threshold = 5
      WHERE low_stock_threshold IS NULL
    `);

    await client.query(`
      UPDATE orders
      SET payment_status = 'pending'
      WHERE payment_status IS NULL
    `);

    await client.query(`
      UPDATE orders
      SET status = 'pending'
      WHERE status IS NULL
    `);

    await client.query(`
      UPDATE order_items
      SET seller_status = 'pending'
      WHERE seller_status IS NULL
    `);

    // --------------------------------------------------------
    // ADMIN SYNC
    // --------------------------------------------------------

    if (
      ADMIN_EMAIL &&
      ADMIN_PASSWORD
    ) {
      const hash =
        await bcrypt.hash(
          ADMIN_PASSWORD,
          10
        );

      const existing =
        await client.query(
          `SELECT id FROM users WHERE email=$1 LIMIT 1`,
          [ADMIN_EMAIL]
        );

      if (existing.rows.length) {
        await client.query(
          `
          UPDATE users
          SET
            role='admin',
            approved=TRUE,
            password_hash=$2,
            name='Admin'
          WHERE email=$1
          `,
          [
            ADMIN_EMAIL,
            hash
          ]
        );
      } else {
        await client.query(
          `
          INSERT INTO users
          (name,email,password_hash,role,approved)
          VALUES
          ('Admin',$1,$2,'admin',TRUE)
          `,
          [
            ADMIN_EMAIL,
            hash
          ]
        );
      }
    }

    await client.query("COMMIT");

    console.log(
      "Database initialized successfully"
    );

  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// ------------------------------------------------------------
// CART CALCULATION
// ------------------------------------------------------------

async function calculateCart(items) {
  if (
    !Array.isArray(items) ||
    !items.length
  ) {
    throw new Error("Cart is empty");
  }

  const ids = items.map(
    x => Number(x.product_id)
  );

  const uniqueIds = [
    ...new Set(ids)
  ];

  const result =
    await pool.query(
      `
      SELECT *
      FROM products
      WHERE id = ANY($1::int[])
        AND approval_status='approved'
      `,
      [uniqueIds]
    );

  const productMap =
    new Map(
      result.rows.map(
        p => [Number(p.id), p]
      )
    );

  let subtotal = 0;

  const normalized = [];

  for (const item of items) {
    const product =
      productMap.get(
        Number(item.product_id)
      );

    if (!product) {
      throw new Error(
        `Product not found: ${item.product_id}`
      );
    }

    const quantity =
      Math.max(
        1,
        Number(item.quantity || 1)
      );

    if (
      Number(product.stock) <
      quantity
    ) {
      throw new Error(
        `${product.name} is out of stock or insufficient stock`
      );
    }

    const lineTotal =
      money(
        Number(product.price) *
        quantity
      );

    subtotal =
      money(
        subtotal +
        lineTotal
      );

    normalized.push({
      product,
      quantity,
      lineTotal
    });
  }

  const shipping_fee =
    shippingFor(subtotal);

  const total =
    money(
      subtotal +
      shipping_fee
    );

  return {
    normalized,
    subtotal,
    shipping_fee,
    total
  };
}

// ------------------------------------------------------------
// GST CALCULATION FOR ORDER
// ------------------------------------------------------------

function calculateItemGST(
  product,
  quantity,
  buyerState
) {
  const amount =
    money(
      Number(product.price) *
      Number(quantity)
    );

  const rate =
    Number(product.gst_rate || 0);

  const result =
    PRICES_INCLUDE_GST
      ? gstFromInclusive(
          amount,
          rate
        )
      : gstFromExclusive(
          amount,
          rate
        );

  const split =
    splitGST(
      result.gst,
      buyerState
    );

  return {
    gst_rate: rate,
    hsn_code: clean(product.hsn_code),
    taxable_amount: result.taxable,
    gst_amount: result.gst,
    cgst_amount: split.cgst,
    sgst_amount: split.sgst,
    igst_amount: split.igst
  };
}

function calculateShippingGST(
  shippingFee,
  buyerState
) {
  const result =
    PRICES_INCLUDE_GST
      ? gstFromInclusive(
          shippingFee,
          SHIPPING_GST_RATE
        )
      : gstFromExclusive(
          shippingFee,
          SHIPPING_GST_RATE
        );

  const split =
    splitGST(
      result.gst,
      buyerState
    );

  return {
    taxable: result.taxable,
    gst: result.gst,
    cgst: split.cgst,
    sgst: split.sgst,
    igst: split.igst
  };
}

// ------------------------------------------------------------
// LOGIN
// ------------------------------------------------------------

async function loginUser(
  email,
  password,
  res
) {
  const result =
    await pool.query(
      `
      SELECT *
      FROM users
      WHERE email=$1
      LIMIT 1
      `,
      [
        clean(email).toLowerCase()
      ]
    );

  if (!result.rows.length) {
    return res.status(401).json({
      error: "Invalid email or password"
    });
  }

  const user =
    result.rows[0];

  const valid =
    await bcrypt.compare(
      String(password || ""),
      user.password_hash
    );

  if (!valid) {
    return res.status(401).json({
      error: "Invalid email or password"
    });
  }

  if (
    user.role === "seller" &&
    !user.approved
  ) {
    return res.status(403).json({
      error:
        "Seller account is waiting for admin approval"
    });
  }

  const token =
    signToken(user);

  return res.json({
    success: true,
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      approved: user.approved
    }
  });
}

app.post(
  "/api/login",
  async (req, res) => {
    try {
      return await loginUser(
        req.body.email,
        req.body.password,
        res
      );
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: "Login failed"
      });
    }
  }
);

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      return await loginUser(
        req.body.email,
        req.body.password,
        res
      );
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: "Login failed"
      });
    }
  }
);

// ------------------------------------------------------------
// REGISTER
// ------------------------------------------------------------

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const name =
        clean(req.body.name);

      const email =
        clean(req.body.email)
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      const requestedRole =
        clean(
          req.body.role ||
          "customer"
        ).toLowerCase();

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password are required"
        });
      }

      const roleValue =
        requestedRole === "seller"
          ? "seller"
          : "customer";

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email=$1
          LIMIT 1
          `,
          [email]
        );

      if (existing.rows.length) {
        return res.status(409).json({
          error:
            "Email already registered"
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          10
        );

      const approved =
        roleValue === "seller"
          ? false
          : true;

      const result =
        await pool.query(
          `
          INSERT INTO users
          (name,email,password_hash,role,approved)
          VALUES($1,$2,$3,$4,$5)
          RETURNING id,name,email,role,approved
          `,
          [
            name,
            email,
            hash,
            roleValue,
            approved
          ]
        );

      const user =
        result.rows[0];

      if (roleValue === "seller") {
        return res.status(201).json({
          success: true,
          message:
            "Seller registration submitted. Admin approval required.",
          user
        });
      }

      const token =
        signToken(user);

      return res.status(201).json({
        success: true,
        token,
        user
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Registration failed"
      });
    }
  }
);

// ------------------------------------------------------------
// PRODUCTS
// ------------------------------------------------------------

app.get(
  "/api/products",
  async (req, res) => {
    try {
      const sellerMode =
        req.query.seller === "me";

      if (sellerMode) {
        return auth(
          req,
          res,
          async () => {
            if (
              !["seller", "admin"].includes(
                req.user.role
              )
            ) {
              return res.status(403).json({
                error:
                  "Seller access required"
              });
            }

            const result =
              req.user.role === "admin"
                ? await pool.query(
                    `
                    SELECT *
                    FROM products
                    ORDER BY id DESC
                    `
                  )
                : await pool.query(
                    `
                    SELECT *
                    FROM products
                    WHERE seller_id=$1
                    ORDER BY id DESC
                    `,
                    [req.user.id]
                  );

            return res.json(
              result.rows
            );
          }
        );
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM products
          WHERE approval_status='approved'
          ORDER BY id DESC
          `
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load products"
      });
    }
  }
);

app.get(
  "/api/products/:id",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM products
          WHERE id=$1
            AND approval_status='approved'
          LIMIT 1
          `,
          [Number(req.params.id)]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Product not found"
        });
      }

      res.json(
        result.rows[0]
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load product"
      });
    }
  }
);

// ------------------------------------------------------------
// SELLER PRODUCTS
// ------------------------------------------------------------

app.get(
  "/api/seller/products",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM products
          WHERE seller_id=$1
          ORDER BY id DESC
          `,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load seller products"
      });
    }
  }
);

app.post(
  "/api/products",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const {
        name,
        description,
        price,
        mrp,
        stock,
        brand,
        sku,
        category,
        images,
        weight,
        size,
        color,
        low_stock_threshold,
        gst_rate,
        hsn_code
      } = req.body;

      if (!clean(name)) {
        return res.status(400).json({
          error:
            "Product name is required"
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO products
          (
            seller_id,
            name,
            description,
            price,
            mrp,
            stock,
            brand,
            sku,
            category,
            images,
            weight,
            size,
            color,
            low_stock_threshold,
            gst_rate,
            hsn_code,
            approval_status,
            created_at,
            updated_at
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            $11,$12,$13,$14,$15,$16,'pending',
            NOW(),NOW()
          )
          RETURNING *
          `,
          [
            req.user.id,
            clean(name),
            clean(description),
            money(price),
            money(mrp),
            Number(stock || 0),
            clean(brand),
            clean(sku),
            clean(category),
            Array.isArray(images)
              ? JSON.stringify(images)
              : "[]",
            Number(weight || 0),
            clean(size),
            clean(color),
            Number(
              low_stock_threshold || 5
            ),
            Number(gst_rate || 0),
            clean(hsn_code)
          ]
        );

      res.status(201).json({
        success: true,
        message:
          "Product submitted for admin approval",
        product:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Product creation failed"
      });
    }
  }
);

// ------------------------------------------------------------
// ADDRESSES
// ------------------------------------------------------------

app.post(
  "/api/addresses",
  auth,
  async (req, res) => {
    try {
      const {
        full_name,
        phone,
        address_line1,
        address_line2,
        landmark,
        city,
        state,
        pincode,
        gstin
      } = req.body;

      if (
        !clean(full_name) ||
        !clean(phone) ||
        !clean(address_line1) ||
        !clean(city) ||
        !clean(state) ||
        !clean(pincode)
      ) {
        return res.status(400).json({
          error:
            "All required address fields are needed"
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO addresses
          (
            user_id,
            full_name,
            phone,
            address_line1,
            address_line2,
            landmark,
            city,
            state,
            pincode,
            gstin
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          RETURNING *
          `,
          [
            req.user.id,
            clean(full_name),
            clean(phone),
            clean(address_line1),
            clean(address_line2),
            clean(landmark),
            clean(city),
            clean(state),
            clean(pincode),
            clean(gstin).toUpperCase()
          ]
        );

      res.status(201).json({
        success: true,
        address:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Address creation failed"
      });
    }
  }
);

app.get(
  "/api/addresses",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM addresses
          WHERE user_id=$1
          ORDER BY id DESC
          `,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load addresses"
      });
    }
  }
);

// ------------------------------------------------------------
// CREATE ORDER - COD
// ------------------------------------------------------------

app.post(
  "/api/orders",
  auth,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const {
        items,
        address_id,
        payment_method
      } = req.body;

      const cart =
        await calculateCart(items);

      const addressResult =
        await client.query(
          `
          SELECT *
          FROM addresses
          WHERE id=$1
            AND user_id=$2
          LIMIT 1
          `,
          [
            Number(address_id),
            req.user.id
          ]
        );

      if (
        !addressResult.rows.length
      ) {
        return res.status(400).json({
          error:
            "Valid delivery address required"
        });
      }

      const address =
        addressResult.rows[0];

      const buyerState =
        clean(address.state);

      let taxableAmount = 0;
      let gstAmount = 0;
      let cgstAmount = 0;
      let sgstAmount = 0;
      let igstAmount = 0;

      const itemTaxes = [];

      for (
        const item of cart.normalized
      ) {
        const tax =
          calculateItemGST(
            item.product,
            item.quantity,
            buyerState
          );

        taxableAmount =
          money(
            taxableAmount +
            tax.taxable_amount
          );

        gstAmount =
          money(
            gstAmount +
            tax.gst_amount
          );

        cgstAmount =
          money(
            cgstAmount +
            tax.cgst_amount
          );

        sgstAmount =
          money(
            sgstAmount +
            tax.sgst_amount
          );

        igstAmount =
          money(
            igstAmount +
            tax.igst_amount
          );

        itemTaxes.push(
          tax
        );
      }

      const shippingGST =
        calculateShippingGST(
          cart.shipping_fee,
          buyerState
        );

      taxableAmount =
        money(
          taxableAmount +
          shippingGST.taxable
        );

      gstAmount =
        money(
          gstAmount +
          shippingGST.gst
        );

      cgstAmount =
        money(
          cgstAmount +
          shippingGST.cgst
        );

      sgstAmount =
        money(
          sgstAmount +
          shippingGST.sgst
        );

      igstAmount =
        money(
          igstAmount +
          shippingGST.igst
        );

      await client.query(
        "BEGIN"
      );

      const orderResult =
        await client.query(
          `
          INSERT INTO orders
          (
            user_id,
            address_id,
            subtotal,
            shipping_fee,
            total,
            payment_method,
            payment_status,
            status,
            delivery_min_days,
            delivery_max_days,
            invoice_date,
            billing_gstin,
            seller_gstin,
            gst_amount,
            cgst_amount,
            sgst_amount,
            igst_amount,
            taxable_amount,
            shipping_taxable_amount,
            shipping_gst_amount
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,
            'pending',
            'pending',
            $7,$8,NOW(),
            $9,$10,$11,$12,$13,$14,
            $15,$16,$17
          )
          RETURNING *
          `,
          [
            req.user.id,
            address.id,
            cart.subtotal,
            cart.shipping_fee,
            cart.total,
            clean(
              payment_method || "COD"
            ).toUpperCase(),
            DELIVERY_MIN_DAYS,
            DELIVERY_MAX_DAYS,
            clean(address.gstin)
              .toUpperCase(),
            BUSINESS_GSTIN,
            gstAmount,
            cgstAmount,
            sgstAmount,
            igstAmount,
            taxableAmount,
            shippingGST.taxable,
            shippingGST.gst
          ]
        );

      const order =
        orderResult.rows[0];

      const invoiceNumber =
        invoiceNumberFor(
          order.id
        );

      await client.query(
        `
        UPDATE orders
        SET invoice_number=$1
        WHERE id=$2
        `,
        [
          invoiceNumber,
          order.id
        ]
      );

      for (
        let i = 0;
        i < cart.normalized.length;
        i++
      ) {
        const item =
          cart.normalized[i];

        const tax =
          itemTaxes[i];

        const product =
          item.product;

        // Lock stock row
        const stockResult =
          await client.query(
            `
            SELECT stock
            FROM products
            WHERE id=$1
            FOR UPDATE
            `,
            [product.id]
          );

        if (
          !stockResult.rows.length ||
          Number(
            stockResult.rows[0].stock
          ) < item.quantity
        ) {
          throw new Error(
            `${product.name} stock changed. Please try again.`
          );
        }

        await client.query(
          `
          UPDATE products
          SET stock=stock-$1,
              updated_at=NOW()
          WHERE id=$2
          `,
          [
            item.quantity,
            product.id
          ]
        );

        await client.query(
          `
          INSERT INTO order_items
          (
            order_id,
            product_id,
            seller_id,
            product_name,
            price,
            quantity,
            seller_status,
            gst_rate,
            hsn_code,
            taxable_amount,
            gst_amount,
            cgst_amount,
            sgst_amount,
            igst_amount
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,'pending',
            $7,$8,$9,$10,$11,$12,$13
          )
          `,
          [
            order.id,
            product.id,
            product.seller_id,
            product.name,
            money(product.price),
            item.quantity,
            tax.gst_rate,
            tax.hsn_code,
            tax.taxable_amount,
            tax.gst_amount,
            tax.cgst_amount,
            tax.sgst_amount,
            tax.igst_amount
          ]
        );
      }

      await client.query(
        "COMMIT"
      );

      const finalOrder =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id=$1
          `,
          [order.id]
        );

      res.status(201).json({
        success: true,
        message:
          "COD order created successfully",
        order:
          finalOrder.rows[0]
      });

    } catch (err) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(err);

      res.status(400).json({
        error:
          err.message ||
          "Order creation failed"
      });

    } finally {
      client.release();
    }
  }
);

// ------------------------------------------------------------
// RAZORPAY CREATE ORDER
// ------------------------------------------------------------

app.post(
  "/api/payment/create-order",
  auth,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      if (!razorpay) {
        return res.status(503).json({
          error:
            "Razorpay is not configured"
        });
      }

      const {
        items,
        address_id
      } = req.body;

      const cart =
        await calculateCart(items);

      const addressResult =
        await client.query(
          `
          SELECT *
          FROM addresses
          WHERE id=$1
            AND user_id=$2
          LIMIT 1
          `,
          [
            Number(address_id),
            req.user.id
          ]
        );

      if (
        !addressResult.rows.length
      ) {
        return res.status(400).json({
          error:
            "Valid delivery address required"
        });
      }

      const address =
        addressResult.rows[0];

      let taxableAmount = 0;
      let gstAmount = 0;
      let cgstAmount = 0;
      let sgstAmount = 0;
      let igstAmount = 0;

      const itemTaxes = [];

      for (
        const item of cart.normalized
      ) {
        const tax =
          calculateItemGST(
            item.product,
            item.quantity,
            address.state
          );

        taxableAmount =
          money(
            taxableAmount +
            tax.taxable_amount
          );

        gstAmount =
          money(
            gstAmount +
            tax.gst_amount
          );

        cgstAmount =
          money(
            cgstAmount +
            tax.cgst_amount
          );

        sgstAmount =
          money(
            sgstAmount +
            tax.sgst_amount
          );

        igstAmount =
          money(
            igstAmount +
            tax.igst_amount
          );

        itemTaxes.push(
          tax
        );
      }

      const shippingGST =
        calculateShippingGST(
          cart.shipping_fee,
          address.state
        );

      taxableAmount =
        money(
          taxableAmount +
          shippingGST.taxable
        );

      gstAmount =
        money(
          gstAmount +
          shippingGST.gst
        );

      cgstAmount =
        money(
          cgstAmount +
          shippingGST.cgst
        );

      sgstAmount =
        money(
          sgstAmount +
          shippingGST.sgst
        );

      igstAmount =
        money(
          igstAmount +
          shippingGST.igst
        );

      const razorOrder =
        await razorpay.orders.create({
          amount:
            Math.round(
              cart.total * 100
            ),
          currency: "INR",
          receipt:
            `SN-${Date.now()}`,
          notes: {
            user_id:
              String(req.user.id)
          }
        });

      await client.query(
        "BEGIN"
      );

      const orderResult =
        await client.query(
          `
          INSERT INTO orders
          (
            user_id,
            address_id,
            subtotal,
            shipping_fee,
            total,
            payment_method,
            payment_status,
            status,
            razorpay_order_id,
            delivery_min_days,
            delivery_max_days,
            invoice_date,
            billing_gstin,
            seller_gstin,
            gst_amount,
            cgst_amount,
            sgst_amount,
            igst_amount,
            taxable_amount,
            shipping_taxable_amount,
            shipping_gst_amount
          )
          VALUES
          (
            $1,$2,$3,$4,$5,'Razorpay',
            'pending',
            'pending',
            $6,$7,$8,NOW(),
            $9,$10,$11,$12,$13,$14,$15,$16,$17
          )
          RETURNING *
          `,
          [
            req.user.id,
            address.id,
            cart.subtotal,
            cart.shipping_fee,
            cart.total,
            razorOrder.id,
            DELIVERY_MIN_DAYS,
            DELIVERY_MAX_DAYS,
            clean(address.gstin)
              .toUpperCase(),
            BUSINESS_GSTIN,
            gstAmount,
            cgstAmount,
            sgstAmount,
            igstAmount,
            taxableAmount,
            shippingGST.taxable,
            shippingGST.gst
          ]
        );

      const order =
        orderResult.rows[0];

      const invoiceNumber =
        invoiceNumberFor(
          order.id
        );

      await client.query(
        `
        UPDATE orders
        SET invoice_number=$1
        WHERE id=$2
        `,
        [
          invoiceNumber,
          order.id
        ]
      );

      for (
        let i = 0;
        i < cart.normalized.length;
        i++
      ) {
        const item =
          cart.normalized[i];

        const tax =
          itemTaxes[i];

        const product =
          item.product;

        await client.query(
          `
          INSERT INTO order_items
          (
            order_id,
            product_id,
            seller_id,
            product_name,
            price,
            quantity,
            seller_status,
            gst_rate,
            hsn_code,
            taxable_amount,
            gst_amount,
            cgst_amount,
            sgst_amount,
            igst_amount
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,'pending',
            $7,$8,$9,$10,$11,$12,$13
          )
          `,
          [
            order.id,
            product.id,
            product.seller_id,
            product.name,
            money(product.price),
            item.quantity,
            tax.gst_rate,
            tax.hsn_code,
            tax.taxable_amount,
            tax.gst_amount,
            tax.cgst_amount,
            tax.sgst_amount,
            tax.igst_amount
          ]
        );
      }

      await client.query(
        "COMMIT"
      );

      res.json({
        success: true,
        razorpay_key_id:
          RAZORPAY_KEY_ID,
        razorpay_order_id:
          razorOrder.id,
        amount:
          razorOrder.amount,
        currency:
          razorOrder.currency,
        order_id:
          order.id,
        invoice_number:
          invoiceNumber
      });

    } catch (err) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(err);

      res.status(400).json({
        error:
          err.message ||
          "Razorpay order creation failed"
      });

    } finally {
      client.release();
    }
  }
);

// ------------------------------------------------------------
// RAZORPAY VERIFY
// ------------------------------------------------------------

app.post(
  "/api/payment/verify",
  auth,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = req.body;

      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          error:
            "Payment verification data missing"
        });
      }

      const generatedSignature =
        crypto
          .createHmac(
            "sha256",
            RAZORPAY_KEY_SECRET
          )
          .update(
            `${razorpay_order_id}|${razorpay_payment_id}`
          )
          .digest("hex");

      if (
        generatedSignature !==
        razorpay_signature
      ) {
        return res.status(400).json({
          error:
            "Invalid payment signature"
        });
      }

      await client.query(
        "BEGIN"
      );

      const orderResult =
        await client.query(
          `
          SELECT *
          FROM orders
          WHERE razorpay_order_id=$1
            AND user_id=$2
          FOR UPDATE
          `,
          [
            razorpay_order_id,
            req.user.id
          ]
        );

      if (
        !orderResult.rows.length
      ) {
        throw new Error(
          "Order not found"
        );
      }

      const order =
        orderResult.rows[0];

      if (
        order.payment_status ===
        "paid"
      ) {
        await client.query(
          "COMMIT"
        );

        return res.json({
          success: true,
          message:
            "Payment already verified",
          order
        });
      }

      const itemsResult =
        await client.query(
          `
          SELECT oi.*, p.stock
          FROM order_items oi
          JOIN products p
            ON p.id=oi.product_id
          WHERE oi.order_id=$1
          FOR UPDATE OF p
          `,
          [order.id]
        );

      for (
        const item of itemsResult.rows
      ) {
        if (
          Number(item.stock) <
          Number(item.quantity)
        ) {
          throw new Error(
            `${item.product_name} is out of stock`
          );
        }
      }

      for (
        const item of itemsResult.rows
      ) {
        await client.query(
          `
          UPDATE products
          SET stock=stock-$1,
              updated_at=NOW()
          WHERE id=$2
          `,
          [
            Number(item.quantity),
            Number(item.product_id)
          ]
        );
      }

      const updated =
        await client.query(
          `
          UPDATE orders
          SET
            payment_status='paid',
            status='confirmed',
            razorpay_payment_id=$1,
            updated_at=NOW()
          WHERE id=$2
          RETURNING *
          `,
          [
            razorpay_payment_id,
            order.id
          ]
        );

      await client.query(
        "COMMIT"
      );

      res.json({
        success: true,
        message:
          "Payment verified successfully",
        order:
          updated.rows[0]
      });

    } catch (err) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(err);

      res.status(400).json({
        error:
          err.message ||
          "Payment verification failed"
      });

    } finally {
      client.release();
    }
  }
);

// ------------------------------------------------------------
// ORDER DETAIL BUILDER
// ------------------------------------------------------------

async function getOrderForUser(
  orderId,
  userId,
  isAdmin = false
) {
  const params =
    isAdmin
      ? [Number(orderId)]
      : [
          Number(orderId),
          Number(userId)
        ];

  const orderResult =
    await pool.query(
      isAdmin
        ? `
          SELECT o.*, a.*
          FROM orders o
          LEFT JOIN addresses a
            ON a.id=o.address_id
          WHERE o.id=$1
          LIMIT 1
          `
        : `
          SELECT o.*, a.*
          FROM orders o
          LEFT JOIN addresses a
            ON a.id=o.address_id
          WHERE o.id=$1
            AND o.user_id=$2
          LIMIT 1
          `,
      params
    );

  if (!orderResult.rows.length) {
    return null;
  }

  const order =
    orderResult.rows[0];

  const itemsResult =
    await pool.query(
      `
      SELECT
        oi.*,
        p.sku,
        p.images,
        p.weight,
        p.category
      FROM order_items oi
      LEFT JOIN products p
        ON p.id=oi.product_id
      WHERE oi.order_id=$1
      ORDER BY oi.id
      `,
      [order.id]
    );

  return {
    ...order,
    items:
      itemsResult.rows
  };
}

// ------------------------------------------------------------
// ORDERS
// ------------------------------------------------------------

app.get(
  "/api/orders",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            o.*,
            a.full_name,
            a.city,
            a.state,
            a.pincode
          FROM orders o
          LEFT JOIN addresses a
            ON a.id=o.address_id
          WHERE o.user_id=$1
          ORDER BY o.id DESC
          `,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load orders"
      });
    }
  }
);

app.get(
  "/api/orders/:id",
  auth,
  async (req, res) => {
    try {
      const order =
        await getOrderForUser(
          req.params.id,
          req.user.id,
          false
        );

      if (!order) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      res.json(order);

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load order"
      });
    }
  }
);

// ------------------------------------------------------------
// SELLER ORDERS
// ------------------------------------------------------------

app.get(
  "/api/seller/orders",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            oi.*,
            o.status AS order_status,
            o.payment_status,
            o.payment_method,
            o.created_at,
            o.address_id,
            a.full_name,
            a.phone,
            a.address_line1,
            a.address_line2,
            a.landmark,
            a.city,
            a.state,
            a.pincode
          FROM order_items oi
          JOIN orders o
            ON o.id=oi.order_id
          LEFT JOIN addresses a
            ON a.id=o.address_id
          WHERE oi.seller_id=$1
          ORDER BY oi.id DESC
          `,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load seller orders"
      });
    }
  }
);

app.put(
  "/api/seller/orders/:id",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const {
        seller_status,
        seller_tracking_number
      } = req.body;

      const allowed = [
        "pending",
        "confirmed",
        "packed",
        "shipped"
      ];

      const newStatus =
        clean(
          seller_status || "pending"
        ).toLowerCase();

      if (
        !allowed.includes(
          newStatus
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid seller status"
        });
      }

      if (
        newStatus === "shipped" &&
        !clean(
          seller_tracking_number
        )
      ) {
        return res.status(400).json({
          error:
            "Tracking number required before shipping"
        });
      }

      const result =
        await pool.query(
          `
          UPDATE order_items
          SET
            seller_status=$1,
            seller_tracking_number=$2,
            seller_updated_at=NOW(),
            seller_shipped_at=
              CASE
                WHEN $1='shipped'
                THEN NOW()
                ELSE seller_shipped_at
              END
          WHERE id=$3
            AND seller_id=$4
          RETURNING *
          `,
          [
            newStatus,
            clean(
              seller_tracking_number
            ),
            Number(req.params.id),
            req.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Seller order item not found"
        });
      }

      res.json({
        success: true,
        item:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Seller order update failed"
      });
    }
  }
);

// ------------------------------------------------------------
// SELLER STATS
// ------------------------------------------------------------

app.get(
  "/api/seller/stats",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const products =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS total_products,
            COUNT(*) FILTER (
              WHERE approval_status='approved'
            )::int AS approved_products,
            COALESCE(
              SUM(stock),0
            )::int AS total_stock
          FROM products
          WHERE seller_id=$1
          `,
          [req.user.id]
        );

      const orders =
        await pool.query(
          `
          SELECT
            COUNT(DISTINCT oi.order_id)::int
              AS total_orders,
            COALESCE(
              SUM(
                oi.price * oi.quantity
              ),0
            ) AS sales
          FROM order_items oi
          WHERE oi.seller_id=$1
          `,
          [req.user.id]
        );

      res.json({
        products:
          products.rows[0],
        orders:
          orders.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load seller stats"
      });
    }
  }
);

// ------------------------------------------------------------
// ADMIN STATS
// ------------------------------------------------------------

app.get(
  "/api/admin/stats",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            (SELECT COUNT(*) FROM users)::int
              AS users,
            (SELECT COUNT(*)
             FROM users
             WHERE role='seller')::int
              AS sellers,
            (SELECT COUNT(*)
             FROM users
             WHERE role='seller'
               AND approved=FALSE)::int
              AS pending_sellers,
            (SELECT COUNT(*) FROM products)::int
              AS products,
            (SELECT COUNT(*)
             FROM products
             WHERE approval_status='pending')::int
              AS pending_products,
            (SELECT COUNT(*) FROM orders)::int
              AS orders,
            (SELECT COALESCE(SUM(total),0)
             FROM orders
             WHERE payment_status='paid'
                OR payment_method='COD') AS sales
        `);

      res.json(
        result.rows[0]
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load admin stats"
      });
    }
  }
);

// ------------------------------------------------------------
// ADMIN SELLERS
// ------------------------------------------------------------

app.get(
  "/api/admin/sellers",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            role,
            approved,
            created_at
          FROM users
          WHERE role='seller'
          ORDER BY id DESC
          `
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load sellers"
      });
    }
  }
);

app.put(
  "/api/admin/sellers/:id",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const approved =
        req.body.approved === true ||
        String(
          req.body.approved
        ).toLowerCase() ===
          "true";

      const result =
        await pool.query(
          `
          UPDATE users
          SET approved=$1
          WHERE id=$2
            AND role='seller'
          RETURNING
            id,name,email,role,approved
          `,
          [
            approved,
            Number(req.params.id)
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Seller not found"
        });
      }

      res.json({
        success: true,
        seller:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Seller update failed"
      });
    }
  }
);

// ------------------------------------------------------------
// ADMIN PRODUCTS
// ------------------------------------------------------------

app.get(
  "/api/admin/products",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            p.*,
            u.name AS seller_name,
            u.email AS seller_email
          FROM products p
          LEFT JOIN users u
            ON u.id=p.seller_id
          ORDER BY p.id DESC
          `
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load admin products"
      });
    }
  }
);

app.put(
  "/api/admin/products/:id",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const status =
        clean(
          req.body.approval_status ||
          req.body.status
        ).toLowerCase();

      const allowed = [
        "pending",
        "approved",
        "rejected"
      ];

      if (
        !allowed.includes(status)
      ) {
        return res.status(400).json({
          error:
            "Invalid product approval status"
        });
      }

      const result =
        await pool.query(
          `
          UPDATE products
          SET
            approval_status=$1,
            updated_at=NOW()
          WHERE id=$2
          RETURNING *
          `,
          [
            status,
            Number(req.params.id)
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Product not found"
        });
      }

      res.json({
        success: true,
        product:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Product approval update failed"
      });
    }
  }
);

// ------------------------------------------------------------
// ADMIN ORDERS
// ------------------------------------------------------------

app.get(
  "/api/admin/orders",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            o.*,
            u.name AS customer_name,
            u.email AS customer_email,
            a.full_name,
            a.phone,
            a.city,
            a.state,
            a.pincode
          FROM orders o
          LEFT JOIN users u
            ON u.id=o.user_id
          LEFT JOIN addresses a
            ON a.id=o.address_id
          ORDER BY o.id DESC
          `
        );

      res.json(
        result.rows
      );

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load admin orders"
      });
    }
  }
);

app.put(
  "/api/admin/orders/:id",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const {
        status,
        tracking_number
      } = req.body;

      const allowed = [
        "pending",
        "confirmed",
        "packed",
        "shipped",
        "out_for_delivery",
        "delivered",
        "cancelled"
      ];

      const newStatus =
        clean(status).toLowerCase();

      if (
        !allowed.includes(
          newStatus
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid order status"
        });
      }

      if (
        newStatus === "shipped" &&
        !clean(tracking_number)
      ) {
        return res.status(400).json({
          error:
            "Tracking number required"
        });
      }

      const result =
        await pool.query(
          `
          UPDATE orders
          SET
            status=$1,
            tracking_number=$2,
            shipped_at=
              CASE
                WHEN $1='shipped'
                THEN COALESCE(shipped_at,NOW())
                ELSE shipped_at
              END,
            delivered_at=
              CASE
                WHEN $1='delivered'
                THEN COALESCE(delivered_at,NOW())
                ELSE delivered_at
              END,
            updated_at=NOW()
          WHERE id=$3
          RETURNING *
          `,
          [
            newStatus,
            clean(tracking_number),
            Number(req.params.id)
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      res.json({
        success: true,
        order:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Order update failed"
      });
    }
  }
);

// ============================================================
// INVOICE
// ============================================================

// ------------------------------------------------------------
// Invoice data
// ------------------------------------------------------------

async function getInvoiceData(
  orderId,
  userId,
  isAdmin = false
) {
  const order =
    await getOrderForUser(
      orderId,
      userId,
      isAdmin
    );

  if (!order) {
    return null;
  }

  // For old orders, calculate missing GST values
  // without changing the checkout total.

  let taxableAmount = 0;
  let gstAmount = 0;
  let cgstAmount = 0;
  let sgstAmount = 0;
  let igstAmount = 0;

  const invoiceItems = [];

  for (const item of order.items) {
    let rate =
      Number(item.gst_rate || 0);

    let lineAmount =
      money(
        Number(item.price) *
        Number(item.quantity)
      );

    let tax;

    if (
      Number(item.taxable_amount || 0) > 0 ||
      Number(item.gst_amount || 0) > 0
    ) {
      tax = {
        taxable:
          money(item.taxable_amount),
        gst:
          money(item.gst_amount),
        cgst:
          money(item.cgst_amount),
        sgst:
          money(item.sgst_amount),
        igst:
          money(item.igst_amount)
      };
    } else {
      const calculated =
        PRICES_INCLUDE_GST
          ? gstFromInclusive(
              lineAmount,
              rate
            )
          : gstFromExclusive(
              lineAmount,
              rate
            );

      const split =
        splitGST(
          calculated.gst,
          order.state
        );

      tax = {
        taxable:
          calculated.taxable,
        gst:
          calculated.gst,
        cgst:
          split.cgst,
        sgst:
          split.sgst,
        igst:
          split.igst
      };
    }

    taxableAmount =
      money(
        taxableAmount +
        tax.taxable
      );

    gstAmount =
      money(
        gstAmount +
        tax.gst
      );

    cgstAmount =
      money(
        cgstAmount +
        tax.cgst
      );

    sgstAmount =
      money(
        sgstAmount +
        tax.sgst
      );

    igstAmount =
      money(
        igstAmount +
        tax.igst
      );

    invoiceItems.push({
      product_id:
        item.product_id,
      name:
        item.product_name,
      hsn_code:
        clean(item.hsn_code),
      quantity:
        Number(item.quantity),
      unit_price:
        money(item.price),
      gst_rate:
        rate,
      taxable_amount:
        tax.taxable,
      gst_amount:
        tax.gst,
      cgst_amount:
        tax.cgst,
      sgst_amount:
        tax.sgst,
      igst_amount:
        tax.igst,
      line_total:
        lineAmount
    });
  }

  const shippingFee =
    money(order.shipping_fee);

  const shippingTax =
    calculateShippingGST(
      shippingFee,
      order.state
    );

  const storedShippingTax =
    Number(
      order.shipping_gst_amount || 0
    );

  const finalShippingGST =
    storedShippingTax > 0
      ? storedShippingTax
      : shippingTax.gst;

  const finalShippingTaxable =
    Number(
      order.shipping_taxable_amount || 0
    ) > 0
      ? money(
          order.shipping_taxable_amount
        )
      : shippingTax.taxable;

  const finalCGST =
    Number(order.cgst_amount || 0);

  const finalSGST =
    Number(order.sgst_amount || 0);

  const finalIGST =
    Number(order.igst_amount || 0);

  return {
    invoice_number:
      order.invoice_number ||
      invoiceNumberFor(order.id),

    invoice_date:
      order.invoice_date ||
      order.created_at,

    order_id:
      order.id,

    seller: {
      name:
        BUSINESS_NAME,
      gstin:
        BUSINESS_GSTIN,
      state:
        BUSINESS_STATE,
      state_code:
        BUSINESS_STATE_CODE,
      address:
        BUSINESS_ADDRESS,
      city:
        BUSINESS_CITY,
      pincode:
        BUSINESS_PINCODE
    },

    buyer: {
      name:
        order.full_name,
      phone:
        order.phone,
      address_line1:
        order.address_line1,
      address_line2:
        order.address_line2,
      landmark:
        order.landmark,
      city:
        order.city,
      state:
        order.state,
      pincode:
        order.pincode,
      gstin:
        order.billing_gstin || ""
    },

    payment: {
      method:
        order.payment_method,
      status:
        order.payment_status
    },

    items:
      invoiceItems,

    shipping: {
      fee:
        shippingFee,
      gst_rate:
        SHIPPING_GST_RATE,
      taxable_amount:
        finalShippingTaxable,
      gst_amount:
        finalShippingGST,
      cgst_amount:
        shippingTax.cgst,
      sgst_amount:
        shippingTax.sgst,
      igst_amount:
        shippingTax.igst
    },

    summary: {
      subtotal:
        money(order.subtotal),

      taxable_amount:
        Number(order.taxable_amount || 0) > 0
          ? money(order.taxable_amount)
          : money(
              taxableAmount +
              finalShippingTaxable
            ),

      gst_amount:
        Number(order.gst_amount || 0) > 0
          ? money(order.gst_amount)
          : money(
              gstAmount +
              finalShippingGST
            ),

      cgst_amount:
        finalCGST > 0
          ? money(finalCGST)
          : money(
              cgstAmount +
              shippingTax.cgst
            ),

      sgst_amount:
        finalSGST > 0
          ? money(finalSGST)
          : money(
              sgstAmount +
              shippingTax.sgst
            ),

      igst_amount:
        finalIGST > 0
          ? money(finalIGST)
          : money(
              igstAmount +
              shippingTax.igst
            ),

      shipping_fee:
        shippingFee,

      grand_total:
        money(order.total)
    },

    courier: {
      provider:
        order.courier_provider || "",
      shipment_id:
        order.shipment_id || "",
      awb_number:
        order.awb_number || "",
      tracking_number:
        order.tracking_number || "",
      status:
        order.courier_status || "",
      label_url:
        order.label_url || "",
      pickup_scheduled_at:
        order.pickup_scheduled_at || null,
      shipped_at:
        order.shipped_at || null,
      delivered_at:
        order.delivered_at || null
    }
  };
}

// ------------------------------------------------------------
// Invoice JSON
// ------------------------------------------------------------

app.get(
  "/api/orders/:id/invoice",
  auth,
  async (req, res) => {
    try {
      const invoice =
        await getInvoiceData(
          req.params.id,
          req.user.id,
          req.user.role === "admin"
        );

      if (!invoice) {
        return res.status(404).json({
          error:
            "Invoice/order not found"
        });
      }

      res.json({
        success: true,
        invoice
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to generate invoice"
      });
    }
  }
);

// ------------------------------------------------------------
// Invoice HTML
// ------------------------------------------------------------

app.get(
  "/api/orders/:id/invoice/html",
  auth,
  async (req, res) => {
    try {
      const invoice =
        await getInvoiceData(
          req.params.id,
          req.user.id,
          req.user.role === "admin"
        );

      if (!invoice) {
        return res.status(404).send(
          "Invoice/order not found"
        );
      }

      const itemRows =
        invoice.items
          .map(
            item => `
              <tr>
                <td>${htmlEscape(item.name)}</td>
                <td>${htmlEscape(item.hsn_code)}</td>
                <td>${item.quantity}</td>
                <td>₹${item.unit_price.toFixed(2)}</td>
                <td>${item.gst_rate}%</td>
                <td>₹${item.taxable_amount.toFixed(2)}</td>
                <td>₹${item.gst_amount.toFixed(2)}</td>
                <td>₹${item.line_total.toFixed(2)}</td>
              </tr>
            `
          )
          .join("");

      const html = `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>
  Invoice ${htmlEscape(invoice.invoice_number)}
</title>

<style>
  * {
    box-sizing: border-box;
  }

  body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 30px;
    color: #222;
    background: #fff;
  }

  .invoice {
    max-width: 1000px;
    margin: auto;
  }

  .top {
    display: flex;
    justify-content: space-between;
    gap: 30px;
    border-bottom: 2px solid #222;
    padding-bottom: 20px;
  }

  h1 {
    margin: 0 0 8px;
  }

  h2 {
    margin-top: 25px;
  }

  .box {
    border: 1px solid #ddd;
    padding: 15px;
    border-radius: 6px;
  }

  .two {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-top: 20px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
  }

  th,
  td {
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
    font-size: 13px;
  }

  th {
    background: #f5f5f5;
  }

  .summary {
    width: 360px;
    margin-left: auto;
    margin-top: 20px;
  }

  .summary div {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
  }

  .grand {
    font-size: 18px;
    font-weight: bold;
    border-top: 2px solid #222;
    margin-top: 8px;
    padding-top: 10px !important;
  }

  .footer {
    margin-top: 40px;
    border-top: 1px solid #ccc;
    padding-top: 15px;
    font-size: 12px;
    color: #555;
  }

  .print-btn {
    position: fixed;
    right: 20px;
    top: 20px;
    padding: 10px 15px;
    cursor: pointer;
  }

  @media print {
    body {
      padding: 0;
    }

    .print-btn {
      display: none;
    }
  }

  @media(max-width:700px) {
    body {
      padding: 10px;
    }

    .top,
    .two {
      display: block;
    }

    .two .box {
      margin-bottom: 15px;
    }

    .summary {
      width: 100%;
    }

    table {
      font-size: 10px;
    }

    th,
    td {
      padding: 5px;
    }
  }
</style>
</head>

<body>

<button
  class="print-btn"
  onclick="window.print()">
  Print / Save PDF
</button>

<div class="invoice">

  <div class="top">

    <div>
      <h1>${htmlEscape(invoice.seller.name)}</h1>

      <div>
        <strong>Tax Invoice</strong>
      </div>

      <div>
        Invoice No:
        ${htmlEscape(invoice.invoice_number)}
      </div>

      <div>
        Invoice Date:
        ${new Date(
          invoice.invoice_date
        ).toLocaleString("en-IN")}
      </div>
    </div>

    <div>
      <strong>GSTIN:</strong>
      ${htmlEscape(
        invoice.seller.gstin ||
        "Not configured"
      )}
      <br>

      ${htmlEscape(
        invoice.seller.address
      )}
      <br>

      ${htmlEscape(
        invoice.seller.city
      )}
      -
      ${htmlEscape(
        invoice.seller.pincode
      )}
      <br>

      ${htmlEscape(
        invoice.seller.state
      )}
    </div>

  </div>

  <div class="two">

    <div class="box">
      <strong>Billed To</strong>

      <p>
        ${htmlEscape(
          invoice.buyer.name
        )}
      </p>

      <p>
        ${htmlEscape(
          invoice.buyer.phone
        )}
      </p>

      <p>
        ${htmlEscape(
          invoice.buyer.address_line1
        )}
        <br>
        ${htmlEscape(
          invoice.buyer.address_line2
        )}
        <br>
        ${htmlEscape(
          invoice.buyer.landmark
        )}
        <br>
        ${htmlEscape(
          invoice.buyer.city
        )},
        ${htmlEscape(
          invoice.buyer.state
        )}
        -
        ${htmlEscape(
          invoice.buyer.pincode
        )}
      </p>

      <p>
        <strong>GSTIN:</strong>
        ${htmlEscape(
          invoice.buyer.gstin ||
          "N/A"
        )}
      </p>
    </div>

    <div class="box">
      <strong>Order Information</strong>

      <p>
        Order ID:
        ${invoice.order_id}
      </p>

      <p>
        Payment:
        ${htmlEscape(
          invoice.payment.method
        )}
      </p>

      <p>
        Payment Status:
        ${htmlEscape(
          invoice.payment.status
        )}
      </p>

      <p>
        Courier:
        ${htmlEscape(
          invoice.courier.provider ||
          "Not assigned"
        )}
      </p>

      <p>
        AWB:
        ${htmlEscape(
          invoice.courier.awb_number ||
          invoice.courier.tracking_number ||
          "Not assigned"
        )}
      </p>
    </div>

  </div>

  <h2>Items</h2>

  <table>
    <thead>
      <tr>
        <th>Product</th>
        <th>HSN</th>
        <th>Qty</th>
        <th>Unit Price</th>
        <th>GST %</th>
        <th>Taxable</th>
        <th>GST</th>
        <th>Total</th>
      </tr>
    </thead>

    <tbody>
      ${itemRows}
    </tbody>
  </table>

  <div class="summary">

    <div>
      <span>Subtotal</span>
      <span>
        ₹${invoice.summary.subtotal.toFixed(2)}
      </span>
    </div>

    <div>
      <span>Shipping</span>
      <span>
        ₹${invoice.summary.shipping_fee.toFixed(2)}
      </span>
    </div>

    <div>
      <span>Taxable Amount</span>
      <span>
        ₹${invoice.summary.taxable_amount.toFixed(2)}
      </span>
    </div>

    <div>
      <span>CGST</span>
      <span>
        ₹${invoice.summary.cgst_amount.toFixed(2)}
      </span>
    </div>

    <div>
      <span>SGST</span>
      <span>
        ₹${invoice.summary.sgst_amount.toFixed(2)}
      </span>
    </div>

    <div>
      <span>IGST</span>
      <span>
        ₹${invoice.summary.igst_amount.toFixed(2)}
      </span>
    </div>

    <div>
      <span>Total GST</span>
      <span>
        ₹${invoice.summary.gst_amount.toFixed(2)}
      </span>
    </div>

    <div class="grand">
      <span>Grand Total</span>
      <span>
        ₹${invoice.summary.grand_total.toFixed(2)}
      </span>
    </div>

  </div>

  <div class="footer">
    <p>
      This is a computer-generated invoice.
    </p>

    <p>
      Thank you for shopping with
      ${htmlEscape(
        invoice.seller.name
      )}.
    </p>
  </div>

</div>

</body>
</html>
      `;

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      res.send(html);

    } catch (err) {
      console.error(err);

      res.status(500).send(
        "Failed to generate invoice"
      );
    }
  }
);

// ============================================================
// SHIPROCKET / COURIER
// ============================================================

// ------------------------------------------------------------
// Shipment details for customer
// ------------------------------------------------------------

app.get(
  "/api/orders/:id/shipment",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            status,
            tracking_number,
            courier_provider,
            shipment_id,
            awb_number,
            courier_status,
            label_url,
            pickup_scheduled_at,
            shipped_at,
            delivered_at
          FROM orders
          WHERE id=$1
            AND user_id=$2
          LIMIT 1
          `,
          [
            Number(req.params.id),
            req.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      res.json({
        success: true,
        shipment:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load shipment"
      });
    }
  }
);

// ------------------------------------------------------------
// Customer tracking
// ------------------------------------------------------------

app.get(
  "/api/orders/:id/tracking",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id=$1
            AND user_id=$2
          LIMIT 1
          `,
          [
            Number(req.params.id),
            req.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      const order =
        result.rows[0];

      if (
        COURIER_PROVIDER ===
          "shiprocket" &&
        order.awb_number &&
        SHIPROCKET_EMAIL &&
        SHIPROCKET_PASSWORD
      ) {
        try {
          const data =
            await shiprocketRequest(
              `/courier/track/awb/${encodeURIComponent(
                order.awb_number
              )}`,
              {
                method: "GET"
              }
            );

          return res.json({
            success: true,
            source: "shiprocket",
            stored:
              order,
            tracking:
              data
          });

        } catch (trackingError) {
          console.error(
            trackingError
          );
        }
      }

      res.json({
        success: true,
        source: "stored",
        tracking: {
          order_id:
            order.id,
          status:
            order.status,
          courier_provider:
            order.courier_provider,
          shipment_id:
            order.shipment_id,
          awb_number:
            order.awb_number,
          tracking_number:
            order.tracking_number,
          courier_status:
            order.courier_status,
          shipped_at:
            order.shipped_at,
          delivered_at:
            order.delivered_at
        }
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Tracking failed"
      });
    }
  }
);

// ------------------------------------------------------------
// ADMIN shipment details
// ------------------------------------------------------------

app.get(
  "/api/admin/orders/:id/shipment",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id=$1
          LIMIT 1
          `,
          [Number(req.params.id)]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      res.json({
        success: true,
        shipment:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Failed to load shipment"
      });
    }
  }
);

// ------------------------------------------------------------
// CREATE SHIPMENT WITH SHIPROCKET
// ------------------------------------------------------------

app.post(
  "/api/admin/orders/:id/shipment",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const orderId =
        Number(req.params.id);

      const orderResult =
        await pool.query(
          `
          SELECT
            o.*,
            a.full_name,
            a.phone,
            a.address_line1,
            a.address_line2,
            a.landmark,
            a.city,
            a.state,
            a.pincode,
            a.gstin,
            u.email
          FROM orders o
          LEFT JOIN addresses a
            ON a.id=o.address_id
          LEFT JOIN users u
            ON u.id=o.user_id
          WHERE o.id=$1
          LIMIT 1
          `,
          [orderId]
        );

      if (!orderResult.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      const order =
        orderResult.rows[0];

      const itemsResult =
        await pool.query(
          `
          SELECT
            oi.*,
            p.sku,
            p.weight,
            p.category
          FROM order_items oi
          LEFT JOIN products p
            ON p.id=oi.product_id
          WHERE oi.order_id=$1
          ORDER BY oi.id
          `,
          [orderId]
        );

      const items =
        itemsResult.rows;

      if (
        !SHIPROCKET_EMAIL ||
        !SHIPROCKET_PASSWORD ||
        !SHIPROCKET_PICKUP_LOCATION
      ) {
        return res.status(503).json({
          success: false,
          mode: "manual",
          message:
            "Shiprocket credentials/pickup location are not configured",
          shipment: {
            courier_provider:
              order.courier_provider || "",
            shipment_id:
              order.shipment_id || "",
            awb_number:
              order.awb_number || "",
            tracking_number:
              order.tracking_number || ""
          }
        });
      }

      let totalWeight =
        0;

      for (const item of items) {
        const weight =
          Number(item.weight || 0) ||
          SHIPROCKET_DEFAULT_WEIGHT;

        totalWeight +=
          weight *
          Number(item.quantity || 1);
      }

      if (totalWeight <= 0) {
        totalWeight =
          SHIPROCKET_DEFAULT_WEIGHT;
      }

      const orderDate =
        new Date(
          order.created_at
        )
          .toISOString()
          .slice(0, 19)
          .replace("T", " ");

      const payload = {
        order_id:
          String(order.id),

        order_date:
          orderDate,

        pickup_location:
          SHIPROCKET_PICKUP_LOCATION,

        billing_customer_name:
          clean(order.full_name),

        billing_last_name:
          "",

        billing_address:
          clean(order.address_line1),

        billing_address_2:
          clean(order.address_line2),

        billing_city:
          clean(order.city),

        billing_pincode:
          clean(order.pincode),

        billing_state:
          clean(order.state),

        billing_country:
          "India",

        billing_email:
          clean(order.email),

        billing_phone:
          clean(order.phone),

        shipping_is_billing:
          true,

        shipping_customer_name:
          clean(order.full_name),

        shipping_last_name:
          "",

        shipping_address:
          clean(order.address_line1),

        shipping_address_2:
          clean(order.address_line2),

        shipping_city:
          clean(order.city),

        shipping_pincode:
          clean(order.pincode),

        shipping_state:
          clean(order.state),

        shipping_country:
          "India",

        shipping_email:
          clean(order.email),

        shipping_phone:
          clean(order.phone),

        order_items:
          items.map(item => ({
            name:
              clean(item.product_name),

            sku:
              clean(item.sku) ||
              `SN-${item.product_id || item.id}`,

            units:
              Number(item.quantity || 1),

            selling_price:
              Number(item.price || 0),

            discount:
              0,

            tax:
              Number(item.gst_rate || 0),

            hsn:
              Number(
                item.hsn_code || 0
              ) || 0
          })),

        payment_method:
          String(
            order.payment_method
          ).toLowerCase() === "cod"
            ? "COD"
            : "Prepaid",

        shipping_charges:
          Number(
            order.shipping_fee || 0
          ),

        giftwrap_charges:
          0,

        transaction_charges:
          0,

        total_discount:
          0,

        sub_total:
          Number(
            order.subtotal || 0
          ),

        length:
          SHIPROCKET_DEFAULT_LENGTH,

        breadth:
          SHIPROCKET_DEFAULT_BREADTH,

        height:
          SHIPROCKET_DEFAULT_HEIGHT,

        weight:
          Number(
            totalWeight.toFixed(3)
          )
      };

      const createData =
        await shiprocketRequest(
          "/orders/create/adhoc",
          {
            method: "POST",
            body:
              JSON.stringify(
                payload
              )
          }
        );

      const shipmentId =
        createData.shipment_id ||
        createData.data?.shipment_id ||
        createData.response?.shipment_id ||
        null;

      const externalOrderId =
        createData.order_id ||
        createData.data?.order_id ||
        createData.response?.order_id ||
        null;

      if (!shipmentId) {
        throw new Error(
          "Shiprocket order created but shipment_id was not returned"
        );
      }

      let awb = "";
      let courierStatus = "";
      let labelUrl = "";

      // ------------------------------------------------------
      // ASSIGN AWB
      // ------------------------------------------------------

      try {
        const awbData =
          await shiprocketRequest(
            "/courier/assign/awb",
            {
              method: "POST",
              body:
                JSON.stringify({
                  shipment_id:
                    shipmentId
                })
            }
          );

        awb =
          awbData.awb_code ||
          awbData.data?.awb_code ||
          awbData.response?.data?.awb_code ||
          awbData.response?.awb_code ||
          "";

        courierStatus =
          awbData.status ||
          awbData.data?.status ||
          awbData.response?.status ||
          "";

        labelUrl =
          awbData.label_url ||
          awbData.data?.label_url ||
          "";
      } catch (awbError) {
        console.error(
          "AWB assignment failed:",
          awbError.message
        );
      }

      // ------------------------------------------------------
      // GENERATE PICKUP
      // ------------------------------------------------------

      let pickupTime = null;

      try {
        const pickupData =
          await shiprocketRequest(
            "/courier/generate/pickup",
            {
              method: "POST",
              body:
                JSON.stringify({
                  shipment_id:
                    shipmentId
                })
            }
          );

        pickupTime =
          pickupData.pickup_scheduled_date ||
          pickupData.data?.pickup_scheduled_date ||
          pickupData.response?.pickup_scheduled_date ||
          null;
      } catch (pickupError) {
        console.error(
          "Pickup generation failed:",
          pickupError.message
        );
      }

      // ------------------------------------------------------
      // SAVE SHIPMENT
      // ------------------------------------------------------

      const saved =
        await pool.query(
          `
          UPDATE orders
          SET
            courier_provider=$1,
            shipment_id=$2,
            awb_number=$3,
            tracking_number=
              CASE
                WHEN $3 <> ''
                THEN $3
                ELSE tracking_number
              END,
            courier_status=$4,
            label_url=$5,
            pickup_scheduled_at=$6,
            updated_at=NOW()
          WHERE id=$7
          RETURNING *
          `,
          [
            "shiprocket",
            String(shipmentId),
            clean(awb),
            clean(courierStatus),
            clean(labelUrl),
            pickupTime,
            orderId
          ]
        );

      res.json({
        success: true,
        message:
          "Shipment created successfully",
        external_order_id:
          externalOrderId,
        shipment_id:
          shipmentId,
        awb_number:
          awb,
        pickup_scheduled_at:
          pickupTime,
        order:
          saved.rows[0]
      });

    } catch (err) {
      console.error(
        "Shipment creation error:",
        err
      );

      res.status(500).json({
        error:
          err.message ||
          "Shipment creation failed"
      });
    }
  }
);

// ------------------------------------------------------------
// MANUAL SHIPMENT UPDATE
// ------------------------------------------------------------

app.put(
  "/api/admin/orders/:id/shipment",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const {
        courier_provider,
        shipment_id,
        awb_number,
        courier_status,
        label_url,
        tracking_number,
        pickup_scheduled_at,
        shipped_at,
        delivered_at
      } = req.body;

      const result =
        await pool.query(
          `
          UPDATE orders
          SET
            courier_provider=$1,
            shipment_id=$2,
            awb_number=$3,
            courier_status=$4,
            label_url=$5,
            tracking_number=$6,
            pickup_scheduled_at=$7,
            shipped_at=$8,
            delivered_at=$9,
            updated_at=NOW()
          WHERE id=$10
          RETURNING *
          `,
          [
            clean(
              courier_provider ||
              ""
            ),
            clean(
              shipment_id ||
              ""
            ),
            clean(
              awb_number ||
              ""
            ),
            clean(
              courier_status ||
              ""
            ),
            clean(
              label_url ||
              ""
            ),
            clean(
              tracking_number ||
              awb_number ||
              ""
            ),
            pickup_scheduled_at ||
              null,
            shipped_at ||
              null,
            delivered_at ||
              null,
            Number(req.params.id)
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      res.json({
        success: true,
        order:
          result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Shipment update failed"
      });
    }
  }
);

// ------------------------------------------------------------
// SHIPROCKET TRACKING - ADMIN
// ------------------------------------------------------------

app.get(
  "/api/admin/orders/:id/shipment/track",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id=$1
          LIMIT 1
          `,
          [Number(req.params.id)]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Order not found"
        });
      }

      const order =
        result.rows[0];

      if (
        !order.awb_number
      ) {
        return res.status(400).json({
          error:
            "AWB number is not available"
        });
      }

      if (
        COURIER_PROVIDER !==
          "shiprocket" ||
        !SHIPROCKET_EMAIL ||
        !SHIPROCKET_PASSWORD
      ) {
        return res.json({
          success: true,
          source: "stored",
          tracking: order
        });
      }

      const data =
        await shiprocketRequest(
          `/courier/track/awb/${encodeURIComponent(
            order.awb_number
          )}`,
          {
            method: "GET"
          }
        );

      res.json({
        success: true,
        source: "shiprocket",
        tracking:
          data
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          err.message ||
          "Courier tracking failed"
      });
    }
  }
);

// ------------------------------------------------------------
// SHIPPING SERVICEABILITY
// ------------------------------------------------------------

app.get(
  "/api/shipping/serviceability",
  async (req, res) => {
    try {
      const pincode =
        clean(req.query.pincode);

      const weight =
        Number(
          req.query.weight ||
          SHIPROCKET_DEFAULT_WEIGHT
        );

      if (!pincode) {
        return res.status(400).json({
          error:
            "Pincode is required"
        });
      }

      if (
        COURIER_PROVIDER !==
          "shiprocket" ||
        !SHIPROCKET_EMAIL ||
        !SHIPROCKET_PASSWORD
      ) {
        return res.json({
          success: true,
          configured: false,
          message:
            "Courier serviceability is not configured",
          pincode,
          weight
        });
      }

      const data =
        await shiprocketRequest(
          `/courier/serviceability/?pincode=${encodeURIComponent(
            pincode
          )}&weight=${encodeURIComponent(
            weight
          )}`,
          {
            method: "GET"
          }
        );

      res.json({
        success: true,
        configured: true,
        pincode,
        weight,
        data
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          err.message ||
          "Serviceability check failed"
      });
    }
  }
);

// ------------------------------------------------------------
// 404
// ------------------------------------------------------------

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "API route not found",
      path:
        req.originalUrl
    });
  }
);

// ------------------------------------------------------------
// ERROR HANDLER
// ------------------------------------------------------------

app.use(
  (err, req, res, next) => {
    console.error(
      "Unhandled error:",
      err
    );

    res.status(500).json({
      error:
        "Internal server error"
    });
  }
);

// ------------------------------------------------------------
// START SERVER
// ------------------------------------------------------------

initDB()
  .then(() => {
    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `ShipNova API v6.0 running on port ${PORT}`
        );

        console.log(
          `Business: ${BUSINESS_NAME}`
        );

        console.log(
          `GST configured: ${
            BUSINESS_GSTIN
              ? "YES"
              : "NO"
          }`
        );

        console.log(
          `Shiprocket configured: ${
            SHIPROCKET_EMAIL &&
            SHIPROCKET_PASSWORD &&
            SHIPROCKET_PICKUP_LOCATION
              ? "YES"
              : "NO"
          }`
        );
      }
    );
  })
  .catch(err => {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  });