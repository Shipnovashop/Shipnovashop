// ============================================================
// SHIPNOVASHOP BACKEND API
// Vercel Frontend + Render Backend + Render PostgreSQL
// ============================================================

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pg = require("pg");

const { Pool } = pg;

const app = express();


// ============================================================
// CONFIG
// ============================================================

const PORT = process.env.PORT || 10000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "change-this-secret-in-render";

const DATABASE_URL =
  process.env.DATABASE_URL;


// ============================================================
// MIDDLEWARE
// ============================================================

app.use(
  cors({
    origin: true,
    credentials: false
  })
);

// Product images can be sent as compressed base64 data URLs.
// 5 MB gives enough room for compressed mobile images.
app.use(
  express.json({
    limit: "5mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "5mb"
  })
);


// ============================================================
// DATABASE
// ============================================================

if (!DATABASE_URL) {
  console.warn(
    "WARNING: DATABASE_URL is not set."
  );
}

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl: DATABASE_URL &&
    !DATABASE_URL.includes("localhost")
    ? {
        rejectUnauthorized: false
      }
    : false
});

pool.on("error", (err) => {
  console.error(
    "Unexpected PostgreSQL pool error:",
    err
  );
});


async function q(text, params = []) {
  return pool.query(text, params);
}


// ============================================================
// JWT
// ============================================================

function tokenFor(user) {
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


// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function auth(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token =
      header.substring(7);

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user = decoded;

    next();

  } catch (err) {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}


// ============================================================
// ROLE MIDDLEWARE
// ============================================================

function requireRole(...roles) {
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


// ============================================================
// HELPERS
// ============================================================

function formatUser(row) {

  if (!row) {
    return null;
  }

  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    created_at: row.created_at,

    business_name:
      row.business_name || null,

    gst_number:
      row.gst_number || null,

    mobile:
      row.mobile || null,

    address:
      row.address || null,

    active:
      row.active !== false
  };
}


function cleanEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}


function normalizeCategory(category) {
  const value =
    String(category || "")
      .trim();

  return value || "Other";
}


// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", async (req, res) => {

  try {

    await q("SELECT 1");

    res.json({
      ok: true,
      database: "connected"
    });

  } catch (err) {

    console.error(
      "Health check error:",
      err
    );

    res.status(500).json({
      ok: false,
      database: "disconnected"
    });
  }
});


// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function init() {

  console.log(
    "Initializing database..."
  );


  // ----------------------------------------------------------
  // USERS
  // ----------------------------------------------------------

  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      email TEXT UNIQUE NOT NULL,

      password TEXT NOT NULL,

      role TEXT NOT NULL
        CHECK (
          role IN (
            'customer',
            'seller',
            'admin'
          )
        ),

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      business_name TEXT,

      gst_number TEXT,

      mobile TEXT,

      address TEXT,

      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);


  // Existing databases migration
  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS business_name TEXT
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS gst_number TEXT
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mobile TEXT
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS address TEXT
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE
  `);


  // Unique GST where GST exists
  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    users_gst_number_unique
    ON users (gst_number)
    WHERE gst_number IS NOT NULL
      AND gst_number <> ''
  `);


  // ----------------------------------------------------------
  // PRODUCTS
  // ----------------------------------------------------------

  await q(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,

      seller_id INTEGER
        NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      name TEXT NOT NULL,

      description TEXT DEFAULT '',

      price NUMERIC(12,2) NOT NULL DEFAULT 0,

      stock INTEGER NOT NULL DEFAULT 0,

      image TEXT DEFAULT '',

      active BOOLEAN NOT NULL DEFAULT TRUE,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);


  // IMPORTANT:
  // Adds category to old existing databases.
  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS category TEXT
    NOT NULL DEFAULT 'Other'
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    products_seller_id_idx
    ON products(seller_id)
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    products_category_idx
    ON products(category)
  `);


  // ----------------------------------------------------------
  // ORDERS
  // ----------------------------------------------------------

  await q(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,

      customer_id INTEGER
        NOT NULL
        REFERENCES users(id),

      total NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
          status IN (
            'pending',
            'confirmed',
            'shipped',
            'delivered',
            'cancelled'
          )
        ),

      created_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP
    )
  `);


  // ----------------------------------------------------------
  // ORDER ITEMS
  // ----------------------------------------------------------

  await q(`
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,

      order_id INTEGER
        NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,

      product_id INTEGER
        REFERENCES products(id)
        ON DELETE SET NULL,

      seller_id INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,

      product_name TEXT NOT NULL,

      price NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      quantity INTEGER
        NOT NULL DEFAULT 1,

      subtotal NUMERIC(12,2)
        NOT NULL DEFAULT 0
    )
  `);


  // ----------------------------------------------------------
  // ADMIN SEED
  // ----------------------------------------------------------

  const adminEmail =
    cleanEmail(
      process.env.ADMIN_EMAIL ||
      "admin@shipnova.local"
    );

  const adminPassword =
    process.env.ADMIN_PASSWORD;


  if (adminPassword) {

    const existingAdmin =
      await q(
        `
        SELECT *
        FROM users
        WHERE email=$1
        LIMIT 1
        `,
        [adminEmail]
      );


    const hashedPassword =
      await bcrypt.hash(
        adminPassword,
        12
      );


    if (existingAdmin.rows.length) {

      await q(
        `
        UPDATE users
        SET
          name=$1,
          password=$2,
          role='admin',
          active=TRUE
        WHERE email=$3
        `,
        [
          "ShipNova Admin",
          hashedPassword,
          adminEmail
        ]
      );

      console.log(
        "Admin account updated:",
        adminEmail
      );

    } else {

      await q(
        `
        INSERT INTO users
          (
            name,
            email,
            password,
            role,
            active
          )
        VALUES
          ($1,$2,$3,'admin',TRUE)
        `,
        [
          "ShipNova Admin",
          adminEmail,
          hashedPassword
        ]
      );

      console.log(
        "Admin account created:",
        adminEmail
      );
    }

  } else {

    console.warn(
      "ADMIN_PASSWORD is not set. " +
      "Admin account was not created/updated."
    );
  }


  console.log(
    "Database initialization complete."
  );
}


// ============================================================
// AUTH - REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const body =
        req.body || {};

      const name =
        String(body.name || "")
          .trim();

      const email =
        cleanEmail(body.email);

      const password =
        String(body.password || "");

      const role =
        String(body.role || "customer")
          .trim()
          .toLowerCase();


      if (!name) {

        return res.status(400).json({
          error: "Name is required"
        });

      }


      if (!email) {

        return res.status(400).json({
          error: "Email is required"
        });

      }


      if (
        password.length < 6
      ) {

        return res.status(400).json({
          error:
            "Password must be at least 6 characters"
        });

      }


      if (
        !["customer", "seller"]
          .includes(role)
      ) {

        return res.status(400).json({
          error: "Invalid registration role"
        });

      }


      // Seller fields
      const businessName =
        String(
          body.businessName ||
          body.business_name ||
          ""
        ).trim();

      const gstNumber =
        String(
          body.gstNumber ||
          body.gst_number ||
          ""
        )
        .trim()
        .toUpperCase();

      const mobile =
        String(
          body.mobile || ""
        ).trim();

      const address =
        String(
          body.address || ""
        ).trim();


      // --------------------------------------------------------
      // SELLER VALIDATION
      // --------------------------------------------------------

      if (role === "seller") {

        if (!businessName) {

          return res.status(400).json({
            error:
              "Business name is required"
          });

        }


        if (!gstNumber) {

          return res.status(400).json({
            error:
              "GST number is required"
          });

        }


        const gstRegex =
          /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;


        if (
          !gstRegex.test(gstNumber)
        ) {

          return res.status(400).json({
            error:
              "Invalid GSTIN format"
          });

        }


        if (mobile) {

          const mobileRegex =
            /^[6-9][0-9]{9}$/;

          if (
            !mobileRegex.test(mobile)
          ) {

            return res.status(400).json({
              error:
                "Invalid mobile number"
            });

          }
        }
      }


      // --------------------------------------------------------
      // EXISTING EMAIL
      // --------------------------------------------------------

      const existing =
        await q(
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


      // --------------------------------------------------------
      // EXISTING GST
      // --------------------------------------------------------

      if (
        role === "seller" &&
        gstNumber
      ) {

        const existingGST =
          await q(
            `
            SELECT id
            FROM users
            WHERE gst_number=$1
            LIMIT 1
            `,
            [gstNumber]
          );


        if (
          existingGST.rows.length
        ) {

          return res.status(409).json({
            error:
              "GST number already registered"
          });

        }
      }


      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );


      const result =
        await q(
          `
          INSERT INTO users
            (
              name,
              email,
              password,
              role,
              business_name,
              gst_number,
              mobile,
              address,
              active
            )
          VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,TRUE)
          RETURNING *
          `,
          [
            name,
            email,
            hashedPassword,
            role,
            role === "seller"
              ? businessName
              : null,
            role === "seller"
              ? gstNumber
              : null,
            role === "seller"
              ? mobile
              : null,
            role === "seller"
              ? address
              : null
          ]
        );


      const user =
        formatUser(
          result.rows[0]
        );


      const token =
        tokenFor(
          result.rows[0]
        );


      res.status(201).json({
        ok: true,
        token,
        user
      });


    } catch (err) {

      console.error(
        "Register error:",
        err
      );


      if (
        err.code === "23505"
      ) {

        return res.status(409).json({
          error:
            "Email or GST number already registered"
        });

      }


      res.status(500).json({
        error:
          "Registration failed"
      });
    }
  }
);


// ============================================================
// AUTH - LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const email =
        cleanEmail(
          req.body?.email
        );

      const password =
        String(
          req.body?.password || ""
        );


      if (!email || !password) {

        return res.status(400).json({
          error:
            "Email and password are required"
        });

      }


      const result =
        await q(
          `
          SELECT *
          FROM users
          WHERE email=$1
          LIMIT 1
          `,
          [email]
        );


      if (!result.rows.length) {

        return res.status(401).json({
          error:
            "Invalid email or password"
        });

      }


      const userRow =
        result.rows[0];


      const valid =
        await bcrypt.compare(
          password,
          userRow.password
        );


      if (!valid) {

        return res.status(401).json({
          error:
            "Invalid email or password"
        });

      }


      if (
        userRow.active === false
      ) {

        return res.status(403).json({
          error:
            "Your account is inactive"
        });

      }


      const token =
        tokenFor(
          userRow
        );


      res.json({
        ok: true,
        token,
        user:
          formatUser(userRow)
      });


    } catch (err) {

      console.error(
        "Login error:",
        err
      );

      res.status(500).json({
        error:
          "Login failed"
      });
    }
  }
);


// ============================================================
// AUTH - CURRENT USER
// ============================================================

app.get(
  "/api/auth/me",
  auth,
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT *
          FROM users
          WHERE id=$1
          LIMIT 1
          `,
          [req.user.id]
        );


      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "User not found"
        });

      }


      res.json({
        ok: true,
        user:
          formatUser(
            result.rows[0]
          )
      });


    } catch (err) {

      console.error(
        "Me error:",
        err
      );

      res.status(500).json({
        error:
          "Unable to load user"
      });
    }
  }
);


// ============================================================
// PRODUCTS - PUBLIC LIST
// ============================================================

app.get(
  "/api/products",
  async (req, res) => {

    try {

      const seller =
        req.query.seller
          ? Number(req.query.seller)
          : null;

      const search =
        String(
          req.query.q || ""
        ).trim();

      const category =
        String(
          req.query.category || ""
        ).trim();


      let sql = `
        SELECT
          p.*,

          u.name AS seller_name,

          u.business_name
            AS seller_business_name

        FROM products p

        JOIN users u
          ON u.id=p.seller_id

        WHERE
          p.active=TRUE
          AND u.active=TRUE
      `;


      const params = [];


      if (
        Number.isInteger(seller)
      ) {

        params.push(seller);

        sql +=
          ` AND p.seller_id=$${params.length}`;
      }


      if (search) {

        params.push(
          `%${search}%`
        );

        sql += `
          AND (
            p.name ILIKE $${params.length}
            OR p.description ILIKE $${params.length}
          )
        `;
      }


      if (category) {

        params.push(category);

        sql +=
          ` AND p.category=$${params.length}`;
      }


      sql += `
        ORDER BY
          p.created_at DESC
      `;


      const result =
        await q(
          sql,
          params
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "GET /api/products error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load products"
      });
    }
  }
);


// ============================================================
// PRODUCT - SINGLE
// ============================================================

app.get(
  "/api/products/:id",
  async (req, res) => {

    try {

      const productId =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(productId)
      ) {

        return res.status(400).json({
          error:
            "Invalid product ID"
        });

      }


      const result =
        await q(
          `
          SELECT
            p.*,

            u.name AS seller_name,

            u.business_name
              AS seller_business_name,

            u.mobile
              AS seller_mobile

          FROM products p

          JOIN users u
            ON u.id=p.seller_id

          WHERE
            p.id=$1
            AND p.active=TRUE
            AND u.active=TRUE

          LIMIT 1
          `,
          [productId]
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

      console.error(
        "GET product error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load product"
      });
    }
  }
);


// ============================================================
// PRODUCT - ADD
// ============================================================

app.post(
  "/api/products",
  auth,
  requireRole("seller", "admin"),
  async (req, res) => {

    try {

      const body =
        req.body || {};


      const name =
        String(
          body.name || ""
        ).trim();


      const category =
        normalizeCategory(
          body.category
        );


      const description =
        String(
          body.description || ""
        ).trim();


      const image =
        String(
          body.image || ""
        ).trim();


      const price =
        Number(body.price);


      const stock =
        Number(body.stock);


      if (!name) {

        return res.status(400).json({
          error:
            "Product name is required"
        });

      }


      if (!Number.isFinite(price) || price < 0) {

        return res.status(400).json({
          error:
            "Invalid price"
        });

      }


      if (!Number.isInteger(stock) || stock < 0) {

        return res.status(400).json({
          error:
            "Invalid stock"
        });

      }


      // --------------------------------------------------------
      // SELLER ACTIVE CHECK
      // --------------------------------------------------------

      const sellerCheck =
        await q(
          `
          SELECT
            id,
            role,
            active
          FROM users
          WHERE id=$1
          LIMIT 1
          `,
          [req.user.id]
        );


      if (!sellerCheck.rows.length) {

        return res.status(403).json({
          error:
            "Seller account not found"
        });

      }


      if (
        req.user.role === "seller" &&
        sellerCheck.rows[0].active === false
      ) {

        return res.status(403).json({
          error:
            "Seller account is inactive"
        });

      }


      const result =
        await q(
          `
          INSERT INTO products
            (
              seller_id,
              name,
              category,
              description,
              price,
              stock,
              image,
              active
            )
          VALUES
            ($1,$2,$3,$4,$5,$6,$7,TRUE)
          RETURNING *
          `,
          [
            req.user.id,
            name,
            category,
            description,
            price,
            stock,
            image
          ]
        );


      res.status(201).json({
        ok: true,
        product:
          result.rows[0]
      });


    } catch (err) {

      console.error(
        "POST /api/products error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to create product"
      });
    }
  }
);


// ============================================================
// PRODUCT - UPDATE
// ============================================================

app.put(
  "/api/products/:id",
  auth,
  requireRole("seller", "admin"),
  async (req, res) => {

    try {

      const productId =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(productId)
      ) {

        return res.status(400).json({
          error:
            "Invalid product ID"
        });

      }


      const existing =
        await q(
          `
          SELECT *
          FROM products
          WHERE id=$1
          LIMIT 1
          `,
          [productId]
        );


      if (!existing.rows.length) {

        return res.status(404).json({
          error:
            "Product not found"
        });

      }


      const product =
        existing.rows[0];


      if (
        req.user.role === "seller" &&
        Number(product.seller_id) !==
          Number(req.user.id)
      ) {

        return res.status(403).json({
          error:
            "You can edit only your own products"
        });

      }


      const body =
        req.body || {};


      const name =
        String(
          body.name || ""
        ).trim();


      const category =
        normalizeCategory(
          body.category
        );


      const description =
        String(
          body.description || ""
        ).trim();


      const image =
        String(
          body.image || ""
        ).trim();


      const price =
        Number(body.price);


      const stock =
        Number(body.stock);


      const active =
        body.active === undefined
          ? product.active !== false
          : Boolean(body.active);


      if (!name) {

        return res.status(400).json({
          error:
            "Product name is required"
        });

      }


      if (!Number.isFinite(price) || price < 0) {

        return res.status(400).json({
          error:
            "Invalid price"
        });

      }


      if (!Number.isInteger(stock) || stock < 0) {

        return res.status(400).json({
          error:
            "Invalid stock"
        });

      }


      const result =
        await q(
          `
          UPDATE products

          SET
            name=$1,
            category=$2,
            description=$3,
            price=$4,
            stock=$5,
            image=$6,
            active=$7

          WHERE id=$8

          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            stock,
            image,
            active,
            productId
          ]
        );


      res.json({
        ok: true,
        product:
          result.rows[0]
      });


    } catch (err) {

      console.error(
        "PUT /api/products/:id error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to update product"
      });
    }
  }
);


// ============================================================
// PRODUCT - DELETE
// ============================================================

app.delete(
  "/api/products/:id",
  auth,
  requireRole("seller", "admin"),
  async (req, res) => {

    try {

      const productId =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(productId)
      ) {

        return res.status(400).json({
          error:
            "Invalid product ID"
        });

      }


      const existing =
        await q(
          `
          SELECT *
          FROM products
          WHERE id=$1
          LIMIT 1
          `,
          [productId]
        );


      if (!existing.rows.length) {

        return res.status(404).json({
          error:
            "Product not found"
        });

      }


      const product =
        existing.rows[0];


      if (
        req.user.role === "seller" &&
        Number(product.seller_id) !==
          Number(req.user.id)
      ) {

        return res.status(403).json({
          error:
            "You can delete only your own products"
        });

      }


      // Check if product was used in an order
      const orderCheck =
        await q(
          `
          SELECT id
          FROM order_items
          WHERE product_id=$1
          LIMIT 1
          `,
          [productId]
        );


      if (orderCheck.rows.length) {

        // Keep order history intact
        await q(
          `
          UPDATE products
          SET active=FALSE
          WHERE id=$1
          `,
          [productId]
        );


        return res.json({
          ok: true,
          message:
            "Product deactivated because it has order history"
        });

      }


      await q(
        `
        DELETE FROM products
        WHERE id=$1
        `,
        [productId]
      );


      res.json({
        ok: true,
        message:
          "Product deleted successfully"
      });


    } catch (err) {

      console.error(
        "DELETE product error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to delete product"
      });
    }
  }
);


// ============================================================
// ORDERS - CREATE
// ============================================================

app.post(
  "/api/orders",
  auth,
  requireRole("customer"),
  async (req, res) => {

    const client =
      await pool.connect();


    try {

      const items =
        Array.isArray(
          req.body?.items
        )
          ? req.body.items
          : [];


      if (!items.length) {

        return res.status(400).json({
          error:
            "Order must contain at least one item"
        });

      }


      await client.query(
        "BEGIN"
      );


      let total = 0;

      const lockedProducts = [];


      // --------------------------------------------------------
      // CHECK PRODUCTS + STOCK
      // --------------------------------------------------------

      for (const item of items) {

        const productId =
          Number(
            item.product_id
          );

        const quantity =
          Number(
            item.quantity
          );


        if (
          !Number.isInteger(productId) ||
          !Number.isInteger(quantity) ||
          quantity <= 0
        ) {

          throw new Error(
            "Invalid order item"
          );

        }


        const result =
          await client.query(
            `
            SELECT
              p.*,

              u.active
                AS seller_active

            FROM products p

            JOIN users u
              ON u.id=p.seller_id

            WHERE
              p.id=$1

            FOR UPDATE OF p
            `,
            [productId]
          );


        if (!result.rows.length) {

          throw new Error(
            `Product ${productId} not found`
          );

        }


        const product =
          result.rows[0];


        if (
          !product.active ||
          !product.seller_active
        ) {

          throw new Error(
            `${product.name} is not available`
          );

        }


        if (
          Number(product.stock) <
          quantity
        ) {

          throw new Error(
            `Insufficient stock for ${product.name}`
          );

        }


        const price =
          Number(
            product.price
          );


        const subtotal =
          price * quantity;


        total += subtotal;


        lockedProducts.push({
          product,
          quantity,
          price,
          subtotal
        });
      }


      // --------------------------------------------------------
      // CREATE ORDER
      // --------------------------------------------------------

      const orderResult =
        await client.query(
          `
          INSERT INTO orders
            (
              customer_id,
              total,
              status
            )
          VALUES
            ($1,$2,'pending')

          RETURNING *
          `,
          [
            req.user.id,
            total
          ]
        );


      const order =
        orderResult.rows[0];


      // --------------------------------------------------------
      // ORDER ITEMS + STOCK
      // --------------------------------------------------------

      for (
        const item
        of lockedProducts
      ) {

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
              subtotal
            )
          VALUES
            ($1,$2,$3,$4,$5,$6,$7)
          `,
          [
            order.id,
            product.id,
            product.seller_id,
            product.name,
            item.price,
            item.quantity,
            item.subtotal
          ]
        );


        await client.query(
          `
          UPDATE products

          SET stock =
            stock - $1

          WHERE id=$2
          `,
          [
            item.quantity,
            product.id
          ]
        );
      }


      await client.query(
        "COMMIT"
      );


      res.status(201).json({
        ok: true,
        order
      });


    } catch (err) {

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}


      console.error(
        "Create order error:",
        err
      );


      res.status(400).json({
        error:
          err.message ||
          "Unable to create order"
      });


    } finally {

      client.release();

    }
  }
);


// ============================================================
// CUSTOMER - MY ORDERS
// ============================================================

app.get(
  "/api/orders",
  auth,
  requireRole("customer"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT
            o.*,

            COALESCE(
              json_agg(
                json_build_object(
                  'id', oi.id,
                  'product_id', oi.product_id,
                  'seller_id', oi.seller_id,
                  'product_name', oi.product_name,
                  'price', oi.price,
                  'quantity', oi.quantity,
                  'subtotal', oi.subtotal
                )
                ORDER BY oi.id
              )
              FILTER (
                WHERE oi.id IS NOT NULL
              ),
              '[]'
            ) AS items

          FROM orders o

          LEFT JOIN order_items oi
            ON oi.order_id=o.id

          WHERE
            o.customer_id=$1

          GROUP BY o.id

          ORDER BY
            o.created_at DESC
          `,
          [req.user.id]
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "Customer orders error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load orders"
      });
    }
  }
);


// ============================================================
// SELLER - ORDERS
// ============================================================

app.get(
  "/api/seller/orders",
  auth,
  requireRole("seller", "admin"),
  async (req, res) => {

    try {

      const sellerId =
        req.user.role === "seller"
          ? req.user.id
          : (
              req.query.seller
                ? Number(req.query.seller)
                : null
            );


      let sql = `
        SELECT

          o.id AS order_id,

          o.total AS order_total,

          o.status,

          o.created_at,

          u.id AS customer_id,

          u.name AS customer_name,

          u.email AS customer_email,

          u.mobile AS customer_mobile,

          oi.id AS item_id,

          oi.product_id,

          oi.product_name,

          oi.price,

          oi.quantity,

          oi.subtotal

        FROM orders o

        JOIN users u
          ON u.id=o.customer_id

        JOIN order_items oi
          ON oi.order_id=o.id

        WHERE 1=1
      `;


      const params = [];


      if (
        Number.isInteger(
          Number(sellerId)
        )
      ) {

        params.push(
          Number(sellerId)
        );

        sql +=
          ` AND oi.seller_id=$${params.length}`;
      }


      sql += `
        ORDER BY
          o.created_at DESC,
          oi.id DESC
      `;


      const result =
        await q(
          sql,
          params
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "Seller orders error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load seller orders"
      });
    }
  }
);


// ============================================================
// ADMIN - ALL ORDERS
// ============================================================

app.get(
  "/api/admin/orders",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT

            o.*,

            u.name
              AS customer_name,

            u.email
              AS customer_email,

            u.mobile
              AS customer_mobile,

            (
              SELECT COUNT(*)
              FROM order_items oi
              WHERE oi.order_id=o.id
            ) AS item_count

          FROM orders o

          JOIN users u
            ON u.id=o.customer_id

          ORDER BY
            o.created_at DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "Admin orders error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load orders"
      });
    }
  }
);


// ============================================================
// ADMIN - ORDER DETAILS
// ============================================================

app.get(
  "/api/admin/orders/:id",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const orderId =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(orderId)
      ) {

        return res.status(400).json({
          error:
            "Invalid order ID"
        });

      }


      const orderResult =
        await q(
          `
          SELECT

            o.*,

            u.name
              AS customer_name,

            u.email
              AS customer_email,

            u.mobile
              AS customer_mobile,

            u.address
              AS customer_address

          FROM orders o

          JOIN users u
            ON u.id=o.customer_id

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


      const itemsResult =
        await q(
          `
          SELECT

            oi.*,

            u.name
              AS seller_name,

            u.business_name
              AS seller_business_name

          FROM order_items oi

          LEFT JOIN users u
            ON u.id=oi.seller_id

          WHERE
            oi.order_id=$1

          ORDER BY
            oi.id
          `,
          [orderId]
        );


      res.json({
        ok: true,

        order:
          orderResult.rows[0],

        items:
          itemsResult.rows
      });


    } catch (err) {

      console.error(
        "Admin order details error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load order details"
      });
    }
  }
);


// ============================================================
// ADMIN - UPDATE ORDER STATUS
// ============================================================

app.put(
  "/api/admin/orders/:id/status",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const orderId =
        Number(
          req.params.id
        );


      const status =
        String(
          req.body?.status || ""
        )
        .trim()
        .toLowerCase();


      const validStatuses = [
        "pending",
        "confirmed",
        "shipped",
        "delivered",
        "cancelled"
      ];


      if (
        !validStatuses.includes(status)
      ) {

        return res.status(400).json({
          error:
            "Invalid order status"
        });

      }


      const result =
        await q(
          `
          UPDATE orders

          SET status=$1

          WHERE id=$2

          RETURNING *
          `,
          [
            status,
            orderId
          ]
        );


      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "Order not found"
        });

      }


      res.json({
        ok: true,
        order:
          result.rows[0]
      });


    } catch (err) {

      console.error(
        "Update order status error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to update order status"
      });
    }
  }
);


// ============================================================
// ADMIN - USERS
// ============================================================

app.get(
  "/api/users",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT
            id,
            name,
            email,
            role,
            created_at,
            business_name,
            gst_number,
            mobile,
            address,
            active

          FROM users

          ORDER BY
            created_at DESC
          `
        );


      res.json(
        result.rows.map(
          formatUser
        )
      );


    } catch (err) {

      console.error(
        "Admin users error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load users"
      });
    }
  }
);


// ============================================================
// ADMIN - DASHBOARD STATS
// ============================================================

app.get(
  "/api/stats",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const usersResult =
        await q(
          `
          SELECT COUNT(*)::int AS count
          FROM users
          `
        );


      const customersResult =
        await q(
          `
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE role='customer'
          `
        );


      const sellersResult =
        await q(
          `
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE role='seller'
          `
        );


      const activeSellersResult =
        await q(
          `
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE
            role='seller'
            AND active=TRUE
          `
        );


      const productsResult =
        await q(
          `
          SELECT COUNT(*)::int AS count
          FROM products
          `
        );


      const ordersResult =
        await q(
          `
          SELECT COUNT(*)::int AS count
          FROM orders
          `
        );


      const revenueResult =
        await q(
          `
          SELECT
            COALESCE(
              SUM(total),
              0
            ) AS revenue

          FROM orders

          WHERE status <> 'cancelled'
          `
        );


      res.json({
        users:
          usersResult.rows[0].count,

        customers:
          customersResult.rows[0].count,

        sellers:
          sellersResult.rows[0].count,

        active_sellers:
          activeSellersResult.rows[0].count,

        products:
          productsResult.rows[0].count,

        orders:
          ordersResult.rows[0].count,

        revenue:
          Number(
            revenueResult.rows[0].revenue || 0
          )
      });


    } catch (err) {

      console.error(
        "Stats error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load dashboard stats"
      });
    }
  }
);


// ============================================================
// ADMIN - ALL PRODUCTS
// ============================================================

app.get(
  "/api/admin/products",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT

            p.*,

            u.name
              AS seller_name,

            u.email
              AS seller_email,

            u.business_name
              AS seller_business_name,

            u.gst_number
              AS seller_gst

          FROM products p

          JOIN users u
            ON u.id=p.seller_id

          ORDER BY
            p.created_at DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "Admin products error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load products"
      });
    }
  }
);


// ============================================================
// ADMIN - SELLERS
// ============================================================

app.get(
  "/api/admin/sellers",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT

            u.id,
            u.name,
            u.email,
            u.business_name,
            u.gst_number,
            u.mobile,
            u.address,
            u.active,
            u.created_at,

            (
              SELECT COUNT(*)
              FROM products p
              WHERE p.seller_id=u.id
            ) AS product_count,

            (
              SELECT COUNT(*)
              FROM order_items oi
              WHERE oi.seller_id=u.id
            ) AS order_item_count

          FROM users u

          WHERE
            u.role='seller'

          ORDER BY
            u.created_at DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "Admin sellers error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load sellers"
      });
    }
  }
);


// ============================================================
// ADMIN - EDIT SELLER
// ============================================================

app.put(
  "/api/admin/sellers/:id",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const sellerId =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(sellerId)
      ) {

        return res.status(400).json({
          error:
            "Invalid seller ID"
        });

      }


      const existing =
        await q(
          `
          SELECT *
          FROM users

          WHERE
            id=$1
            AND role='seller'

          LIMIT 1
          `,
          [sellerId]
        );


      if (!existing.rows.length) {

        return res.status(404).json({
          error:
            "Seller not found"
        });

      }


      const body =
        req.body || {};


      const name =
        String(
          body.name ||
          existing.rows[0].name ||
          ""
        ).trim();


      const email =
        cleanEmail(
          body.email ||
          existing.rows[0].email
        );


      const businessName =
        String(
          body.businessName ||
          body.business_name ||
          existing.rows[0].business_name ||
          ""
        ).trim();


      const gstNumber =
        String(
          body.gstNumber ||
          body.gst_number ||
          existing.rows[0].gst_number ||
          ""
        )
        .trim()
        .toUpperCase();


      const mobile =
        String(
          body.mobile ??
          existing.rows[0].mobile ??
          ""
        ).trim();


      const address =
        String(
          body.address ??
          existing.rows[0].address ??
          ""
        ).trim();


      if (!name || !email) {

        return res.status(400).json({
          error:
            "Name and email are required"
        });

      }


      const emailCheck =
        await q(
          `
          SELECT id
          FROM users
          WHERE
            email=$1
            AND id<>$2
          LIMIT 1
          `,
          [
            email,
            sellerId
          ]
        );


      if (emailCheck.rows.length) {

        return res.status(409).json({
          error:
            "Email already in use"
        });

      }


      if (gstNumber) {

        const gstCheck =
          await q(
            `
            SELECT id
            FROM users

            WHERE
              gst_number=$1
              AND id<>$2

            LIMIT 1
            `,
            [
              gstNumber,
              sellerId
            ]
          );


        if (
          gstCheck.rows.length
        ) {

          return res.status(409).json({
            error:
              "GST number already in use"
          });

        }
      }


      const result =
        await q(
          `
          UPDATE users

          SET
            name=$1,
            email=$2,
            business_name=$3,
            gst_number=$4,
            mobile=$5,
            address=$6

          WHERE
            id=$7
            AND role='seller'

          RETURNING *
          `,
          [
            name,
            email,
            businessName || null,
            gstNumber || null,
            mobile || null,
            address || null,
            sellerId
          ]
        );


      res.json({
        ok: true,
        seller:
          formatUser(
            result.rows[0]
          )
      });


    } catch (err) {

      console.error(
        "Edit seller error:",
        err
      );


      if (
        err.code === "23505"
      ) {

        return res.status(409).json({
          error:
            "Email or GST number already in use"
        });

      }


      res.status(500).json({
        error:
          "Failed to update seller"
      });
    }
  }
);


// ============================================================
// ADMIN - ACTIVATE / DEACTIVATE SELLER
// ============================================================

app.put(
  "/api/admin/sellers/:id/status",
  auth,
  requireRole("admin"),
  async (req, res) => {

    try {

      const sellerId =
        Number(
          req.params.id
        );


      const active =
        Boolean(
          req.body?.active
        );


      if (
        !Number.isInteger(sellerId)
      ) {

        return res.status(400).json({
          error:
            "Invalid seller ID"
        });

      }


      const result =
        await q(
          `
          UPDATE users

          SET active=$1

          WHERE
            id=$2
            AND role='seller'

          RETURNING *
          `,
          [
            active,
            sellerId
          ]
        );


      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "Seller not found"
        });

      }


      res.json({
        ok: true,
        seller:
          formatUser(
            result.rows[0]
          )
      });


    } catch (err) {

      console.error(
        "Seller status error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to update seller status"
      });
    }
  }
);


// ============================================================
// PUBLIC - SELLERS
// ============================================================

app.get(
  "/api/sellers",
  async (req, res) => {

    try {

      const result =
        await q(
          `
          SELECT

            id,
            name,
            business_name,
            mobile,
            address,
            created_at

          FROM users

          WHERE
            role='seller'
            AND active=TRUE

          ORDER BY
            business_name ASC,
            name ASC
          `
        );


      res.json(
        result.rows
      );


    } catch (err) {

      console.error(
        "Public sellers error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to load sellers"
      });
    }
  }
);


// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {

    res.status(404).json({
      error:
        "API endpoint not found",
      path:
        req.originalUrl
    });

  }
);


// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (err, req, res, next) => {

    console.error(
      "Unhandled server error:",
      err
    );


    if (
      err.type ===
      "entity.too.large"
    ) {

      return res.status(413).json({
        error:
          "Request too large. Please use a smaller image."
      });

    }


    res.status(500).json({
      error:
        "Internal server error"
    });

  }
);


// ============================================================
// START SERVER
// ============================================================

async function start() {

  try {

    await init();


    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `ShipNova API listening on port ${PORT}`
        );

      }
    );


  } catch (err) {

    console.error(
      "Server startup failed:",
      err
    );

    process.exit(1);

  }
}


start();