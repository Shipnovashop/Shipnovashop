const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pg = require("pg");

const { Pool } = pg;

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
       !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

app.use(cors({
  origin: true,
  credentials: false
}));

app.use(express.json({ limit: "5mb" }));

const q = (text, params = []) => pool.query(text, params);

function tokenFor(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function formatUser(row) {
  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    businessName: row.business_name || "",
    gstNumber: row.gst_number || "",
    mobile: row.mobile || "",
    address: row.address || "",
    active: row.active !== false,
    createdAt: row.created_at
  };
}

async function init() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer'
        CHECK (role IN ('customer','seller','admin')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      business_name TEXT,
      gst_number TEXT,
      mobile TEXT,
      address TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);

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

  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_gst_unique
    ON users(gst_number)
    WHERE gst_number IS NOT NULL AND gst_number <> ''
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      stock INTEGER NOT NULL DEFAULT 0,
      image TEXT DEFAULT '',
      category TEXT NOT NULL DEFAULT 'Other',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Existing database में category जोड़ देगा
  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'Other'
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_products_seller
    ON products(seller_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_products_category
    ON products(category)
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL REFERENCES users(id),
      total NUMERIC(12,2) NOT NULL DEFAULT 0,
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
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL,
      seller_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      price NUMERIC(12,2) NOT NULL,
      quantity INTEGER NOT NULL,
      subtotal NUMERIC(12,2) NOT NULL
    )
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_order_items_order
    ON order_items(order_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_order_items_seller
    ON order_items(seller_id)
  `);

  // Admin account
  if (process.env.ADMIN_PASSWORD) {
    const email =
      String(process.env.ADMIN_EMAIL || "admin@shipnova.local")
        .trim()
        .toLowerCase();

    const password = process.env.ADMIN_PASSWORD;

    const hash = await bcrypt.hash(password, 12);

    const existing = await q(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [email]
    );

    if (existing.rows.length) {
      await q(
        `
        UPDATE users
        SET
          name = 'ShipNova Admin',
          password = $1,
          role = 'admin',
          active = TRUE
        WHERE email = $2
        `,
        [hash, email]
      );
    } else {
      await q(
        `
        INSERT INTO users
          (name,email,password,role,active)
        VALUES
          ('ShipNova Admin',$1,$2,'admin',TRUE)
        `,
        [email, hash]
      );
    }

    console.log(`Admin account ready: ${email}`);
  } else {
    console.warn(
      "ADMIN_PASSWORD is not set. Admin account was not created/updated."
    );
  }
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", async (req, res) => {
  try {
    await q("SELECT 1");

    res.json({
      ok: true,
      database: "connected"
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      ok: false,
      database: "error"
    });
  }
});

/* =========================
   AUTH
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const body = req.body || {};

    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    const role =
      body.role === "seller"
        ? "seller"
        : "customer";

    const businessName =
      String(body.businessName || "").trim();

    const gstNumber =
      String(body.gstNumber || "").trim().toUpperCase();

    const mobile =
      String(body.mobile || "").trim();

    const address =
      String(body.address || "").trim();

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

    if (!password || password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    if (role === "seller") {
      if (!businessName) {
        return res.status(400).json({
          error: "Business name is required"
        });
      }

      if (!gstNumber) {
        return res.status(400).json({
          error: "GST number is required"
        });
      }

      const gstRegex =
        /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;

      if (!gstRegex.test(gstNumber)) {
        return res.status(400).json({
          error: "Invalid GST number format"
        });
      }

      if (mobile) {
        const mobileRegex = /^[6-9][0-9]{9}$/;

        if (!mobileRegex.test(mobile)) {
          return res.status(400).json({
            error: "Invalid mobile number"
          });
        }
      }
    }

    const existing = await q(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [email]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    if (gstNumber) {
      const gstExisting = await q(
        `
        SELECT id
        FROM users
        WHERE gst_number = $1
        LIMIT 1
        `,
        [gstNumber]
      );

      if (gstExisting.rows.length) {
        return res.status(409).json({
          error: "GST number already registered"
        });
      }
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await q(
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
        hash,
        role,
        businessName || null,
        gstNumber || null,
        mobile || null,
        address || null
      ]
    );

    const user = formatUser(result.rows[0]);
    const token = tokenFor(result.rows[0]);

    res.status(201).json({
      ok: true,
      token,
      user
    });
  } catch (err) {
    console.error("Register error:", err);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const result = await q(
      `
      SELECT *
      FROM users
      WHERE email = $1
      LIMIT 1
      `,
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const row = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      row.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    if (row.active === false) {
      return res.status(403).json({
        error: "Account is inactive"
      });
    }

    res.json({
      ok: true,
      token: tokenFor(row),
      user: formatUser(row)
    });
  } catch (err) {
    console.error("Login error:", err);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(
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

function role(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Access denied"
      });
    }

    next();
  };
}

/* =========================
   CURRENT USER
========================= */

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const result = await q(
      `
      SELECT *
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json({
      ok: true,
      user: formatUser(result.rows[0])
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Could not load user"
    });
  }
});

/* =========================
   PUBLIC PRODUCTS
========================= */

app.get("/api/products", async (req, res) => {
  try {
    const params = [];
    const where = [
      "p.active = TRUE",
      "u.active = TRUE",
      "u.role = 'seller'"
    ];

    if (req.query.seller) {
      params.push(Number(req.query.seller));

      where.push(
        `p.seller_id = $${params.length}`
      );
    }

    if (req.query.category) {
      params.push(
        String(req.query.category).trim()
      );

      where.push(
        `LOWER(p.category) = LOWER($${params.length})`
      );
    }

    if (req.query.q) {
      params.push(
        `%${String(req.query.q).trim()}%`
      );

      where.push(`
        (
          p.name ILIKE $${params.length}
          OR p.description ILIKE $${params.length}
          OR p.category ILIKE $${params.length}
          OR u.name ILIKE $${params.length}
          OR u.business_name ILIKE $${params.length}
        )
      `);
    }

    const result = await q(
      `
      SELECT
        p.*,
        u.name AS seller_name,
        u.business_name AS seller_business_name
      FROM products p
      JOIN users u
        ON u.id = p.seller_id
      WHERE ${where.join(" AND ")}
      ORDER BY p.created_at DESC
      `,
      params
    );

    res.json({
      ok: true,
      products: result.rows
    });
  } catch (err) {
    console.error("Products error:", err);

    res.status(500).json({
      error: "Could not load products"
    });
  }
});

/* =========================
   SINGLE PRODUCT
========================= */

app.get("/api/products/:id", async (req, res) => {
  try {
    const result = await q(
      `
      SELECT
        p.*,
        u.name AS seller_name,
        u.business_name AS seller_business_name
      FROM products p
      JOIN users u
        ON u.id = p.seller_id
      WHERE p.id = $1
      LIMIT 1
      `,
      [Number(req.params.id)]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Product not found"
      });
    }

    res.json({
      ok: true,
      product: result.rows[0]
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Could not load product"
    });
  }
});

/* =========================
   ADD PRODUCT
========================= */

app.post(
  "/api/products",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const body = req.body || {};

      const name =
        String(body.name || "").trim();

      const description =
        String(body.description || "").trim();

      const image =
        String(body.image || "").trim();

      const category =
        String(body.category || "Other").trim() ||
        "Other";

      const price = Number(body.price);
      const stock = Number(body.stock);

      if (!name) {
        return res.status(400).json({
          error: "Product name is required"
        });
      }

      if (!Number.isFinite(price) || price < 0) {
        return res.status(400).json({
          error: "Invalid price"
        });
      }

      if (!Number.isInteger(stock) || stock < 0) {
        return res.status(400).json({
          error: "Invalid stock"
        });
      }

      const seller = await q(
        `
        SELECT id, active
        FROM users
        WHERE id = $1
          AND role = 'seller'
        LIMIT 1
        `,
        [req.user.id]
      );

      if (!seller.rows.length) {
        return res.status(404).json({
          error: "Seller not found"
        });
      }

      if (seller.rows[0].active === false) {
        return res.status(403).json({
          error: "Seller account is inactive"
        });
      }

      const result = await q(
        `
        INSERT INTO products
        (
          seller_id,
          name,
          description,
          price,
          stock,
          image,
          category,
          active
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,TRUE)
        RETURNING *
        `,
        [
          req.user.id,
          name,
          description,
          price,
          stock,
          image,
          category
        ]
      );

      res.status(201).json({
        ok: true,
        product: result.rows[0]
      });
    } catch (err) {
      console.error("Add product error:", err);

      res.status(500).json({
        error: "Could not add product"
      });
    }
  }
);

/* =========================
   UPDATE PRODUCT
========================= */

app.put(
  "/api/products/:id",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const body = req.body || {};

      const name =
        String(body.name || "").trim();

      const description =
        String(body.description || "").trim();

      const image =
        String(body.image || "").trim();

      const category =
        String(body.category || "Other").trim() ||
        "Other";

      const price = Number(body.price);
      const stock = Number(body.stock);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid product ID"
        });
      }

      if (!name) {
        return res.status(400).json({
          error: "Product name is required"
        });
      }

      if (!Number.isFinite(price) || price < 0) {
        return res.status(400).json({
          error: "Invalid price"
        });
      }

      if (!Number.isInteger(stock) || stock < 0) {
        return res.status(400).json({
          error: "Invalid stock"
        });
      }

      const result = await q(
        `
        UPDATE products
        SET
          name = $1,
          description = $2,
          price = $3,
          stock = $4,
          image = $5,
          category = $6
        WHERE id = $7
          AND seller_id = $8
        RETURNING *
        `,
        [
          name,
          description,
          price,
          stock,
          image,
          category,
          id,
          req.user.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Product not found"
        });
      }

      res.json({
        ok: true,
        product: result.rows[0]
      });
    } catch (err) {
      console.error("Update product error:", err);

      res.status(500).json({
        error: "Could not update product"
      });
    }
  }
);

/* =========================
   DELETE PRODUCT
========================= */

app.delete(
  "/api/products/:id",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const used = await q(
        `
        SELECT id
        FROM order_items
        WHERE product_id = $1
        LIMIT 1
        `,
        [id]
      );

      let result;

      if (used.rows.length) {
        result = await q(
          `
          UPDATE products
          SET active = FALSE
          WHERE id = $1
            AND seller_id = $2
          RETURNING *
          `,
          [id, req.user.id]
        );
      } else {
        result = await q(
          `
          DELETE FROM products
          WHERE id = $1
            AND seller_id = $2
          RETURNING *
          `,
          [id, req.user.id]
        );
      }

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Product not found"
        });
      }

      res.json({
        ok: true,
        message: used.rows.length
          ? "Product deactivated"
          : "Product deleted"
      });
    } catch (err) {
      console.error("Delete product error:", err);

      res.status(500).json({
        error: "Could not delete product"
      });
    }
  }
);

/* =========================
   CREATE ORDER
========================= */

app.post(
  "/api/orders",
  auth,
  role("customer"),
  async (req, res) => {
    const client = await pool.connect();

    try {
      const items = Array.isArray(req.body.items)
        ? req.body.items
        : [];

      if (!items.length) {
        return res.status(400).json({
          error: "Cart is empty"
        });
      }

      await client.query("BEGIN");

      let total = 0;
      const finalItems = [];

      for (const item of items) {
        const productId = Number(item.product_id);
        const quantity = Number(item.quantity);

        if (
          !Number.isInteger(productId) ||
          !Number.isInteger(quantity) ||
          quantity <= 0
        ) {
          throw new Error("Invalid order item");
        }

        const productResult = await client.query(
          `
          SELECT
            p.*,
            u.active AS seller_active
          FROM products p
          JOIN users u
            ON u.id = p.seller_id
          WHERE p.id = $1
          FOR UPDATE
          `,
          [productId]
        );

        if (!productResult.rows.length) {
          throw new Error(
            `Product ${productId} not found`
          );
        }

        const product = productResult.rows[0];

        if (!product.active) {
          throw new Error(
            `${product.name} is not available`
          );
        }

        if (!product.seller_active) {
          throw new Error(
            `${product.name} seller is inactive`
          );
        }

        if (product.stock < quantity) {
          throw new Error(
            `Insufficient stock for ${product.name}`
          );
        }

        const price = Number(product.price);
        const subtotal = price * quantity;

        total += subtotal;

        finalItems.push({
          product,
          quantity,
          price,
          subtotal
        });
      }

      const orderResult = await client.query(
        `
        INSERT INTO orders
          (customer_id,total,status)
        VALUES
          ($1,$2,'pending')
        RETURNING *
        `,
        [req.user.id, total]
      );

      const order = orderResult.rows[0];

      for (const item of finalItems) {
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
            item.product.id,
            item.product.seller_id,
            item.product.name,
            item.price,
            item.quantity,
            item.subtotal
          ]
        );

        await client.query(
          `
          UPDATE products
          SET stock = stock - $1
          WHERE id = $2
          `,
          [
            item.quantity,
            item.product.id
          ]
        );
      }

      await client.query("COMMIT");

      res.status(201).json({
        ok: true,
        order
      });
    } catch (err) {
      await client.query("ROLLBACK");

      console.error("Create order error:", err);

      res.status(400).json({
        error: err.message || "Could not create order"
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   CUSTOMER ORDERS
========================= */

app.get(
  "/api/orders",
  auth,
  role("customer"),
  async (req, res) => {
    try {
      const result = await q(
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
            ) FILTER (WHERE oi.id IS NOT NULL),
            '[]'
          ) AS items
        FROM orders o
        LEFT JOIN order_items oi
          ON oi.order_id = o.id
        WHERE o.customer_id = $1
        GROUP BY o.id
        ORDER BY o.created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        orders: result.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load orders"
      });
    }
  }
);

/* =========================
   SELLER ORDERS
========================= */

app.get(
  "/api/seller/orders",
  auth,
  role("seller"),
  async (req, res) => {
    try {
      const result = await q(
        `
        SELECT
          o.id,
          o.customer_id,
          o.total,
          o.status,
          o.created_at,
          u.name AS customer_name,
          u.email AS customer_email,
          u.mobile AS customer_mobile,
          u.address AS customer_address,
          COALESCE(
            json_agg(
              json_build_object(
                'id', oi.id,
                'product_id', oi.product_id,
                'product_name', oi.product_name,
                'price', oi.price,
                'quantity', oi.quantity,
                'subtotal', oi.subtotal
              )
              ORDER BY oi.id
            ) FILTER (WHERE oi.id IS NOT NULL),
            '[]'
          ) AS items
        FROM orders o
        JOIN users u
          ON u.id = o.customer_id
        JOIN order_items oi
          ON oi.order_id = o.id
        WHERE oi.seller_id = $1
        GROUP BY
          o.id,
          u.id
        ORDER BY o.created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        ok: true,
        orders: result.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load seller orders"
      });
    }
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/users",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result = await q(
        `
        SELECT
          id,
          name,
          email,
          role,
          business_name,
          gst_number,
          mobile,
          address,
          active,
          created_at
        FROM users
        ORDER BY created_at DESC
        `
      );

      res.json({
        ok: true,
        users: result.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load users"
      });
    }
  }
);

/* =========================
   ADMIN ORDERS
========================= */

app.get(
  "/api/admin/orders",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result = await q(
        `
        SELECT
          o.*,
          u.name AS customer_name,
          u.email AS customer_email,
          u.mobile AS customer_mobile,
          u.address AS customer_address,
          COUNT(oi.id)::INTEGER AS item_count
        FROM orders o
        JOIN users u
          ON u.id = o.customer_id
        LEFT JOIN order_items oi
          ON oi.order_id = o.id
        GROUP BY
          o.id,
          u.id
        ORDER BY o.created_at DESC
        `
      );

      res.json({
        ok: true,
        orders: result.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load admin orders"
      });
    }
  }
);

/* =========================
   ADMIN ORDER DETAILS
========================= */

app.get(
  "/api/admin/orders/:id",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const orderResult = await q(
        `
        SELECT
          o.*,
          u.name AS customer_name,
          u.email AS customer_email,
          u.mobile AS customer_mobile,
          u.address AS customer_address
        FROM orders o
        JOIN users u
          ON u.id = o.customer_id
        WHERE o.id = $1
        LIMIT 1
        `,
        [Number(req.params.id)]
      );

      if (!orderResult.rows.length) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      const itemsResult = await q(
        `
        SELECT *
        FROM order_items
        WHERE order_id = $1
        ORDER BY id
        `,
        [Number(req.params.id)]
      );

      res.json({
        ok: true,
        order: {
          ...orderResult.rows[0],
          items: itemsResult.rows
        }
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load order"
      });
    }
  }
);

/* =========================
   ADMIN ORDER STATUS
========================= */

app.put(
  "/api/admin/orders/:id/status",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const status =
        String(req.body.status || "")
          .trim()
          .toLowerCase();

      const allowed = [
        "pending",
        "confirmed",
        "shipped",
        "delivered",
        "cancelled"
      ];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          error: "Invalid order status"
        });
      }

      const result = await q(
        `
        UPDATE orders
        SET status = $1
        WHERE id = $2
        RETURNING *
        `,
        [
          status,
          Number(req.params.id)
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      res.json({
        ok: true,
        order: result.rows[0]
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not update order status"
      });
    }
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/stats",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result = await q(`
        SELECT
          (SELECT COUNT(*) FROM users)::INTEGER
            AS users,

          (SELECT COUNT(*)
           FROM users
           WHERE role = 'customer')::INTEGER
            AS customers,

          (SELECT COUNT(*)
           FROM users
           WHERE role = 'seller')::INTEGER
            AS sellers,

          (SELECT COUNT(*)
           FROM users
           WHERE role = 'seller'
             AND active = TRUE)::INTEGER
            AS active_sellers,

          (SELECT COUNT(*)
           FROM products)::INTEGER
            AS products,

          (SELECT COUNT(*)
           FROM products
           WHERE active = TRUE)::INTEGER
            AS active_products,

          (SELECT COUNT(*)
           FROM orders)::INTEGER
            AS orders,

          COALESCE(
            (SELECT SUM(total)
             FROM orders
             WHERE status <> 'cancelled'),
            0
          )::NUMERIC(12,2)
            AS revenue
      `);

      res.json({
        ok: true,
        stats: result.rows[0]
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load statistics"
      });
    }
  }
);

/* =========================
   ADMIN PRODUCTS
========================= */

app.get(
  "/api/admin/products",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result = await q(`
        SELECT
          p.*,
          u.name AS seller_name,
          u.email AS seller_email,
          u.business_name AS seller_business_name
        FROM products p
        JOIN users u
          ON u.id = p.seller_id
        ORDER BY p.created_at DESC
      `);

      res.json({
        ok: true,
        products: result.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load products"
      });
    }
  }
);

/* =========================
   ADMIN SELLERS
========================= */

app.get(
  "/api/admin/sellers",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const result = await q(`
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

          COUNT(p.id)::INTEGER AS product_count

        FROM users u

        LEFT JOIN products p
          ON p.seller_id = u.id

        WHERE u.role = 'seller'

        GROUP BY u.id

        ORDER BY u.created_at DESC
      `);

      res.json({
        ok: true,
        sellers: result.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not load sellers"
      });
    }
  }
);

/* =========================
   ADMIN EDIT SELLER
========================= */

app.put(
  "/api/admin/sellers/:id",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const name =
        String(req.body.name || "").trim();

      const businessName =
        String(req.body.businessName || "").trim();

      const gstNumber =
        String(req.body.gstNumber || "")
          .trim()
          .toUpperCase();

      const mobile =
        String(req.body.mobile || "").trim();

      const address =
        String(req.body.address || "").trim();

      if (!name) {
        return res.status(400).json({
          error: "Name is required"
        });
      }

      const result = await q(
        `
        UPDATE users
        SET
          name = $1,
          business_name = $2,
          gst_number = $3,
          mobile = $4,
          address = $5
        WHERE id = $6
          AND role = 'seller'
        RETURNING *
        `,
        [
          name,
          businessName || null,
          gstNumber || null,
          mobile || null,
          address || null,
          id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Seller not found"
        });
      }

      res.json({
        ok: true,
        seller: formatUser(result.rows[0])
      });
    } catch (err) {
      console.error(err);

      if (err.code === "23505") {
        return res.status(409).json({
          error: "GST number already registered"
        });
      }

      res.status(500).json({
        error: "Could not update seller"
      });
    }
  }
);

/* =========================
   ADMIN SELLER STATUS
========================= */

app.put(
  "/api/admin/sellers/:id/status",
  auth,
  role("admin"),
  async (req, res) => {
    try {
      const active =
        req.body.active === true ||
        req.body.active === "true";

      const result = await q(
        `
        UPDATE users
        SET active = $1
        WHERE id = $2
          AND role = 'seller'
        RETURNING *
        `,
        [
          active,
          Number(req.params.id)
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Seller not found"
        });
      }

      res.json({
        ok: true,
        seller: formatUser(result.rows[0])
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Could not update seller status"
      });
    }
  }
);

/* =========================
   PUBLIC SELLERS
========================= */

app.get("/api/sellers", async (req, res) => {
  try {
    const result = await q(`
      SELECT
        u.id,
        u.name,
        u.business_name,
        u.mobile,
        u.address,
        COUNT(p.id)::INTEGER AS product_count
      FROM users u
      LEFT JOIN products p
        ON p.seller_id = u.id
       AND p.active = TRUE
      WHERE u.role = 'seller'
        AND u.active = TRUE
      GROUP BY u.id
      ORDER BY u.name
    `);

    res.json({
      ok: true,
      sellers: result.rows
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Could not load sellers"
    });
  }
});

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    error: "API route not found"
  });
});

/* =========================
   ERROR
========================= */

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  res.status(500).json({
    error: "Internal server error"
  });
});

/* =========================
   START
========================= */

async function start() {
  try {
    await init();

    app.listen(PORT, () => {
      console.log(
        `ShipNova API listening on port ${PORT}`
      );
    });
  } catch (err) {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  }
}

start();