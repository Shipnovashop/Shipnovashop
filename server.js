const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pg = require("pg");

const { Pool } = pg;

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret-in-render";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL is not set.");
}

/*
  Image data can be sent as base64 from seller.html.
  5mb gives enough room for compressed product images.
*/
app.use(express.json({ limit: "5mb" }));

app.use(
  cors({
    origin: true,
    credentials: false
  })
);


/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});


async function q(text, params = []) {
  return pool.query(text, params);
}


/* =========================================================
   JWT
========================================================= */

function tokenFor(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token = header.slice(7);

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      error: "Invalid or expired token"
    });

  }
}


/* =========================================================
   ROLE MIDDLEWARE
========================================================= */

function role(...roles) {

  return function(req, res, next) {

    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Access denied"
      });
    }

    next();

  };

}


/* =========================================================
   HELPERS
========================================================= */

function clean(value) {

  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  return String(value).trim();

}


function formatUser(row) {

  if (!row) {
    return null;
  }

  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,

    businessName:
      row.business_name || "",

    gstNumber:
      row.gst_number || "",

    mobile:
      row.mobile || "",

    address:
      row.address || "",

    active:
      row.active !== false,

    createdAt:
      row.created_at
  };

}


function isValidGST(gst) {

  if (!gst) {
    return false;
  }

  return /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(
    gst.toUpperCase()
  );

}


function isValidMobile(mobile) {

  if (!mobile) {
    return false;
  }

  return /^[6-9][0-9]{9}$/.test(
    mobile
  );

}


function normalizeCategory(category) {

  const value =
    clean(category) || "Other";

  return value.slice(0, 100);

}


/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {

  try {

    await q("SELECT 1");

    res.json({
      ok: true,
      database: "connected"
    });

  } catch (error) {

    console.error(
      "Health check error:",
      error
    );

    res.status(500).json({
      ok: false,
      database: "disconnected"
    });

  }

});


/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function init() {

  console.log("Initializing database...");


  /* =========================
     USERS
  ========================= */

  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      email TEXT NOT NULL UNIQUE,

      password TEXT NOT NULL,

      role TEXT NOT NULL DEFAULT 'customer'
        CHECK (
          role IN ('customer', 'seller', 'admin')
        ),

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      business_name TEXT,

      gst_number TEXT,

      mobile TEXT,

      address TEXT,

      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);


  /* =========================
     USERS MIGRATION
  ========================= */

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


  /*
    Unique GST only when GST is actually provided.
  */

  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    idx_users_gst_unique
    ON users(gst_number)
    WHERE gst_number IS NOT NULL
      AND gst_number <> ''
  `);


  /* =========================
     PRODUCTS
  ========================= */

  await q(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,

      seller_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      name TEXT NOT NULL,

      description TEXT,

      price NUMERIC(12,2) NOT NULL DEFAULT 0,

      stock INTEGER NOT NULL DEFAULT 0,

      image TEXT,

      category TEXT NOT NULL DEFAULT 'Other',

      active BOOLEAN NOT NULL DEFAULT TRUE,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /*
    IMPORTANT:
    Existing ShipNovaShop databases may already
    have the products table without category.

    This safely adds category without deleting data.
  */

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS category TEXT
  `);


  await q(`
    UPDATE products
    SET category = 'Other'
    WHERE category IS NULL
       OR TRIM(category) = ''
  `);


  await q(`
    ALTER TABLE products
    ALTER COLUMN category
    SET DEFAULT 'Other'
  `);


  await q(`
    ALTER TABLE products
    ALTER COLUMN category
    SET NOT NULL
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_products_seller
    ON products(seller_id)
  `);


  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_products_category
    ON products(category)
  `);


  /* =========================
     ORDERS
  ========================= */

  await q(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,

      customer_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

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

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /* =========================
     ORDER ITEMS
  ========================= */

  await q(`
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,

      order_id INTEGER NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,

      product_id INTEGER NOT NULL,

      seller_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      product_name TEXT NOT NULL,

      price NUMERIC(12,2) NOT NULL,

      quantity INTEGER NOT NULL,

      subtotal NUMERIC(12,2) NOT NULL
    )
  `);


  /* =========================
     ADMIN ACCOUNT
  ========================= */

  await createOrUpdateAdmin();


  console.log("✅ Database initialization completed.");

}


/* =========================================================
   ADMIN SEED
========================================================= */

async function createOrUpdateAdmin() {

  const email =
    clean(
      process.env.ADMIN_EMAIL
    ).toLowerCase();

  const password =
    process.env.ADMIN_PASSWORD;


  if (!email || !password) {

    console.warn(
      "⚠️ ADMIN_EMAIL or ADMIN_PASSWORD is not set. Admin account was not created/updated."
    );

    return;

  }


  const hash =
    await bcrypt.hash(
      password,
      12
    );


  const existing =
    await q(
      `
        SELECT id
        FROM users
        WHERE email = $1
        LIMIT 1
      `,
      [email]
    );


  if (existing.rows.length) {

    await q(
      `
        UPDATE users
        SET
          name = 'ShipNova Admin',
          password = $2,
          role = 'admin',
          active = TRUE
        WHERE email = $1
      `,
      [
        email,
        hash
      ]
    );

    console.log(
      "✅ Admin account updated:",
      email
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
        (
          'ShipNova Admin',
          $1,
          $2,
          'admin',
          TRUE
        )
      `,
      [
        email,
        hash
      ]
    );

    console.log(
      "✅ Admin account created:",
      email
    );

  }

}


/* =========================================================
   AUTH REGISTER
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const body =
        req.body || {};


      const name =
        clean(body.name);

      const email =
        clean(body.email).toLowerCase();

      const password =
        String(body.password || "");

      const roleValue =
        clean(body.role || "customer").toLowerCase();


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
          error:
            "Password must be at least 6 characters"
        });

      }


      if (
        !["customer", "seller"].includes(
          roleValue
        )
      ) {

        return res.status(400).json({
          error: "Invalid registration role"
        });

      }


      let businessName = null;
      let gstNumber = null;
      let mobile = null;
      let address = null;


      if (roleValue === "seller") {

        businessName =
          clean(body.businessName);

        gstNumber =
          clean(body.gstNumber)
            .toUpperCase();

        mobile =
          clean(body.mobile);

        address =
          clean(body.address);


        if (!businessName) {

          return res.status(400).json({
            error:
              "Business Name is required"
          });

        }


        if (!gstNumber) {

          return res.status(400).json({
            error:
              "GST Number is required"
          });

        }


        if (!isValidGST(gstNumber)) {

          return res.status(400).json({
            error:
              "Invalid GSTIN format"
          });

        }


        if (!mobile) {

          return res.status(400).json({
            error:
              "Mobile number is required"
          });

        }


        if (!isValidMobile(mobile)) {

          return res.status(400).json({
            error:
              "Invalid mobile number"
          });

        }


        if (!address) {

          return res.status(400).json({
            error:
              "Address is required"
          });

        }

      }


      const existing =
        await q(
          `
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER($1)
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


      if (roleValue === "seller") {

        const existingGST =
          await q(
            `
              SELECT id
              FROM users
              WHERE gst_number = $1
              LIMIT 1
            `,
            [gstNumber]
          );


        if (existingGST.rows.length) {

          return res.status(409).json({
            error:
              "GSTIN is already registered"
          });

        }

      }


      const passwordHash =
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
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8,
              TRUE
            )
            RETURNING *
          `,
          [
            name,
            email,
            passwordHash,
            roleValue,
            businessName,
            gstNumber,
            mobile,
            address
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


      return res.status(201).json({
        message:
          "Registration successful",
        token,
        user
      });


    } catch (error) {

      console.error(
        "Register error:",
        error
      );


      if (
        error.code === "23505"
      ) {

        return res.status(409).json({
          error:
            "Email or GSTIN already registered"
        });

      }


      return res.status(500).json({
        error:
          "Registration failed"
      });

    }

  }
);


/* =========================================================
   AUTH LOGIN
========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const email =
        clean(
          req.body?.email
        ).toLowerCase();

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
            WHERE LOWER(email) = LOWER($1)
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


      if (userRow.active === false) {

        return res.status(403).json({
          error:
            "Your account is inactive"
        });

      }


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


      const token =
        tokenFor(
          userRow
        );


      return res.json({
        message:
          "Login successful",
        token,
        user:
          formatUser(
            userRow
          )
      });


    } catch (error) {

      console.error(
        "Login error:",
        error
      );


      return res.status(500).json({
        error:
          "Login failed"
      });

    }

  }
);


/* =========================================================
   AUTH ME
========================================================= */

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
            WHERE id = $1
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


      if (
        result.rows[0].active === false
      ) {

        return res.status(403).json({
          error:
            "Your account is inactive"
        });

      }


      return res.json({
        user:
          formatUser(
            result.rows[0]
          )
      });


    } catch (error) {

      console.error(
        "Me error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load user"
      });

    }

  }
);


/* =========================================================
   GET PRODUCTS - PUBLIC
========================================================= */

app.get(
  "/api/products",
  async (req, res) => {

    try {

      const seller =
        req.query.seller;

      const search =
        clean(req.query.q);

      const category =
        clean(req.query.category);


      const conditions = [
        "p.active = TRUE",
        "u.active = TRUE"
      ];

      const params = [];


      if (seller) {

        params.push(
          Number(seller)
        );

        conditions.push(
          `p.seller_id = $${params.length}`
        );

      }


      if (search) {

        params.push(
          `%${search}%`
        );

        conditions.push(
          `(
            p.name ILIKE $${params.length}
            OR p.description ILIKE $${params.length}
          )`
        );

      }


      if (category) {

        params.push(
          category
        );

        conditions.push(
          `LOWER(p.category) = LOWER($${params.length})`
        );

      }


      const result =
        await q(
          `
            SELECT
              p.*,

              u.name AS seller_name,

              u.business_name
                AS seller_business_name

            FROM products p

            JOIN users u
              ON u.id = p.seller_id

            WHERE ${conditions.join(" AND ")}

            ORDER BY p.created_at DESC
          `,
          params
        );


      return res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Products error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load products"
      });

    }

  }
);


/* =========================================================
   GET SINGLE PRODUCT
========================================================= */

app.get(
  "/api/products/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (!Number.isInteger(id)) {

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
                AS seller_business_name

            FROM products p

            JOIN users u
              ON u.id = p.seller_id

            WHERE
              p.id = $1
              AND p.active = TRUE
              AND u.active = TRUE

            LIMIT 1
          `,
          [id]
        );


      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "Product not found"
        });

      }


      return res.json(
        result.rows[0]
      );


    } catch (error) {

      console.error(
        "Single product error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load product"
      });

    }

  }
);


/* =========================================================
   ADD PRODUCT
========================================================= */

app.post(
  "/api/products",
  auth,
  role("seller", "admin"),
  async (req, res) => {

    try {

      const body =
        req.body || {};


      const name =
        clean(body.name);

      const description =
        clean(body.description);

      const image =
        clean(body.image);

      const category =
        normalizeCategory(
          body.category
        );

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


      if (
        !Number.isFinite(price) ||
        price < 0
      ) {

        return res.status(400).json({
          error:
            "Invalid product price"
        });

      }


      if (
        !Number.isInteger(stock) ||
        stock < 0
      ) {

        return res.status(400).json({
          error:
            "Invalid product stock"
        });

      }


      let sellerId =
        req.user.id;


      if (req.user.role === "admin") {

        const requestedSeller =
          Number(body.seller_id);

        if (
          Number.isInteger(
            requestedSeller
          )
        ) {

          sellerId =
            requestedSeller;

        }

      }


      const sellerResult =
        await q(
          `
            SELECT
              id,
              role,
              active
            FROM users
            WHERE id = $1
            LIMIT 1
          `,
          [sellerId]
        );


      if (!sellerResult.rows.length) {

        return res.status(404).json({
          error:
            "Seller not found"
        });

      }


      const seller =
        sellerResult.rows[0];


      if (
        seller.role !== "seller" &&
        seller.role !== "admin"
      ) {

        return res.status(400).json({
          error:
            "Invalid seller"
        });

      }


      if (seller.active === false) {

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
              description,
              price,
              stock,
              image,
              category,
              active
            )
            VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              TRUE
            )
            RETURNING *
          `,
          [
            sellerId,
            name,
            description,
            price,
            stock,
            image,
            category
          ]
        );


      return res.status(201).json({
        message:
          "Product added successfully",
        product:
          result.rows[0]
      });


    } catch (error) {

      console.error(
        "Add product error:",
        error
      );


      return res.status(500).json({
        error:
          "Failed to add product"
      });

    }

  }
);


/* =========================================================
   UPDATE PRODUCT
========================================================= */

app.put(
  "/api/products/:id",
  auth,
  role("seller", "admin"),
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (!Number.isInteger(id)) {

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
            WHERE id = $1
            LIMIT 1
          `,
          [id]
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
            "You can only edit your own products"
        });

      }


      const body =
        req.body || {};


      const name =
        clean(
          body.name ??
          product.name
        );

      const description =
        clean(
          body.description ??
          product.description
        );

      const image =
        clean(
          body.image ??
          product.image
        );

      const category =
        normalizeCategory(
          body.category ??
          product.category
        );


      const price =
        Number(
          body.price ??
          product.price
        );

      const stock =
        Number(
          body.stock ??
          product.stock
        );


      let active =
        product.active;


      if (
        body.active !== undefined
      ) {

        active =
          Boolean(body.active);

      }


      if (!name) {

        return res.status(400).json({
          error:
            "Product name is required"
        });

      }


      if (
        !Number.isFinite(price) ||
        price < 0
      ) {

        return res.status(400).json({
          error:
            "Invalid product price"
        });

      }


      if (
        !Number.isInteger(stock) ||
        stock < 0
      ) {

        return res.status(400).json({
          error:
            "Invalid product stock"
        });

      }


      const result =
        await q(
          `
            UPDATE products

            SET
              name = $1,
              description = $2,
              price = $3,
              stock = $4,
              image = $5,
              category = $6,
              active = $7

            WHERE id = $8

            RETURNING *
          `,
          [
            name,
            description,
            price,
            stock,
            image,
            category,
            active,
            id
          ]
        );


      return res.json({
        message:
          "Product updated successfully",
        product:
          result.rows[0]
      });


    } catch (error) {

      console.error(
        "Update product error:",
        error
      );


      return res.status(500).json({
        error:
          "Failed to update product"
      });

    }

  }
);


/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  "/api/products/:id",
  auth,
  role("seller", "admin"),
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (!Number.isInteger(id)) {

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
            WHERE id = $1
            LIMIT 1
          `,
          [id]
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
            "You can only delete your own products"
        });

      }


      const orderItem =
        await q(
          `
            SELECT id
            FROM order_items
            WHERE product_id = $1
            LIMIT 1
          `,
          [id]
        );


      if (orderItem.rows.length) {

        await q(
          `
            UPDATE products
            SET active = FALSE
            WHERE id = $1
          `,
          [id]
        );


        return res.json({
          message:
            "Product has existing orders, so it was deactivated instead of permanently deleted."
        });

      }


      await q(
        `
          DELETE FROM products
          WHERE id = $1
        `,
        [id]
      );


      return res.json({
        message:
          "Product deleted successfully."
      });


    } catch (error) {

      console.error(
        "Delete product error:",
        error
      );


      return res.status(500).json({
        error:
          "Failed to delete product"
      });

    }

  }
);


/* =========================================================
   CREATE ORDER
========================================================= */

app.post(
  "/api/orders",
  auth,
  role("customer"),
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
            "Order must contain at least one product"
        });

      }


      await client.query(
        "BEGIN"
      );


      let total = 0;

      const orderItems = [];


      for (const item of items) {

        const productId =
          Number(
            item.product_id ??
            item.productId
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


        const productResult =
          await client.query(
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
            "Product not found: " +
            productId
          );

        }


        const product =
          productResult.rows[0];


        if (
          !product.active ||
          !product.seller_active
        ) {

          throw new Error(
            `Product "${product.name}" is not available`
          );

        }


        if (
          Number(product.stock) <
          quantity
        ) {

          throw new Error(
            `Insufficient stock for "${product.name}"`
          );

        }


        const price =
          Number(
            product.price
          );


        const subtotal =
          price * quantity;


        total += subtotal;


        orderItems.push({
          product,
          quantity,
          price,
          subtotal
        });

      }


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
            (
              $1,
              $2,
              'pending'
            )
            RETURNING *
          `,
          [
            req.user.id,
            total
          ]
        );


      const order =
        orderResult.rows[0];


      for (
        const item of orderItems
      ) {

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
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7
            )
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


      await client.query(
        "COMMIT"
      );


      return res.status(201).json({
        message:
          "Order placed successfully",
        order
      });


    } catch (error) {

      await client.query(
        "ROLLBACK"
      );


      console.error(
        "Create order error:",
        error
      );


      return res.status(400).json({
        error:
          error.message ||
          "Failed to create order"
      });


    } finally {

      client.release();

    }

  }
);


/* =========================================================
   CUSTOMER ORDERS
========================================================= */

app.get(
  "/api/orders",
  auth,
  role("customer"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
            SELECT
              o.id,
              o.total,
              o.status,
              o.created_at,

              COALESCE(
                JSON_AGG(
                  JSON_BUILD_OBJECT(
                    'id', oi.id,
                    'product_id', oi.product_id,
                    'seller_id', oi.seller_id,
                    'product_name', oi.product_name,
                    'price', oi.price,
                    'quantity', oi.quantity,
                    'subtotal', oi.subtotal
                  )
                )
                FILTER (
                  WHERE oi.id IS NOT NULL
                ),
                '[]'
              ) AS items

            FROM orders o

            LEFT JOIN order_items oi
              ON oi.order_id = o.id

            WHERE
              o.customer_id = $1

            GROUP BY
              o.id

            ORDER BY
              o.created_at DESC
          `,
          [req.user.id]
        );


      return res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Customer orders error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load orders"
      });

    }

  }
);


/* =========================================================
   SELLER ORDERS
========================================================= */

app.get(
  "/api/seller/orders",
  auth,
  role("seller"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
            SELECT
              o.id,
              o.customer_id,
              o.total,
              o.status,
              o.created_at,

              c.name AS customer_name,
              c.email AS customer_email,
              c.mobile AS customer_mobile,
              c.address AS customer_address,

              COALESCE(
                JSON_AGG(
                  JSON_BUILD_OBJECT(
                    'id', oi.id,
                    'product_id', oi.product_id,
                    'product_name', oi.product_name,
                    'price', oi.price,
                    'quantity', oi.quantity,
                    'subtotal', oi.subtotal
                  )
                )
                FILTER (
                  WHERE oi.id IS NOT NULL
                ),
                '[]'
              ) AS items

            FROM orders o

            JOIN order_items oi
              ON oi.order_id = o.id
             AND oi.seller_id = $1

            JOIN users c
              ON c.id = o.customer_id

            GROUP BY
              o.id,
              c.id

            ORDER BY
              o.created_at DESC
          `,
          [req.user.id]
        );


      return res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Seller orders error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load seller orders"
      });

    }

  }
);


/* =========================================================
   ADMIN - ALL ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
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

              COUNT(oi.id)::INTEGER
                AS item_count

            FROM orders o

            JOIN users u
              ON u.id = o.customer_id

            LEFT JOIN order_items oi
              ON oi.order_id = o.id

            GROUP BY
              o.id,
              u.id

            ORDER BY
              o.created_at DESC
          `
        );


      return res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Admin orders error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load admin orders"
      });

    }

  }
);


/* =========================================================
   ADMIN - ORDER DETAILS
========================================================= */

app.get(
  "/api/admin/orders/:id",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const orderId =
        Number(req.params.id);


      if (!Number.isInteger(orderId)) {

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

              u.name AS seller_name,

              u.business_name
                AS seller_business_name

            FROM order_items oi

            LEFT JOIN users u
              ON u.id = oi.seller_id

            WHERE
              oi.order_id = $1

            ORDER BY
              oi.id ASC
          `,
          [orderId]
        );


      return res.json({
        order:
          orderResult.rows[0],

        items:
          itemsResult.rows
      });


    } catch (error) {

      console.error(
        "Admin order details error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load order details"
      });

    }

  }
);


/* =========================================================
   ADMIN - UPDATE ORDER STATUS
========================================================= */

app.put(
  "/api/admin/orders/:id/status",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const orderId =
        Number(req.params.id);

      const status =
        clean(
          req.body?.status
        ).toLowerCase();


      const allowed = [
        "pending",
        "confirmed",
        "shipped",
        "delivered",
        "cancelled"
      ];


      if (!Number.isInteger(orderId)) {

        return res.status(400).json({
          error:
            "Invalid order ID"
        });

      }


      if (!allowed.includes(status)) {

        return res.status(400).json({
          error:
            "Invalid order status"
        });

      }


      const result =
        await q(
          `
            UPDATE orders

            SET status = $1

            WHERE id = $2

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


      return res.json({
        message:
          "Order status updated",
        order:
          result.rows[0]
      });


    } catch (error) {

      console.error(
        "Order status error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to update order status"
      });

    }

  }
);


/* =========================================================
   ADMIN - USERS
========================================================= */

app.get(
  "/api/users",
  auth,
  role("admin"),
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
              business_name,
              gst_number,
              mobile,
              address,
              active,
              created_at

            FROM users

            ORDER BY
              created_at DESC
          `
        );


      return res.json(
        result.rows.map(
          formatUser
        )
      );


    } catch (error) {

      console.error(
        "Users error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load users"
      });

    }

  }
);


/* =========================================================
   ADMIN - DASHBOARD STATS
========================================================= */

app.get(
  "/api/stats",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
            SELECT

              (
                SELECT COUNT(*)
                FROM users
              )::INTEGER
              AS users,

              (
                SELECT COUNT(*)
                FROM users
                WHERE role = 'customer'
              )::INTEGER
              AS customers,

              (
                SELECT COUNT(*)
                FROM users
                WHERE role = 'seller'
              )::INTEGER
              AS sellers,

              (
                SELECT COUNT(*)
                FROM users
                WHERE role = 'seller'
                  AND active = TRUE
              )::INTEGER
              AS active_sellers,

              (
                SELECT COUNT(*)
                FROM products
              )::INTEGER
              AS products,

              (
                SELECT COUNT(*)
                FROM orders
              )::INTEGER
              AS orders,

              COALESCE(
                (
                  SELECT SUM(total)
                  FROM orders
                  WHERE status <> 'cancelled'
                ),
                0
              )::NUMERIC(12,2)
              AS revenue
          `
        );


      return res.json(
        result.rows[0]
      );


    } catch (error) {

      console.error(
        "Stats error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load dashboard stats"
      });

    }

  }
);


/* =========================================================
   ADMIN - ALL PRODUCTS
========================================================= */

app.get(
  "/api/admin/products",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
            SELECT
              p.*,

              u.name AS seller_name,

              u.email AS seller_email,

              u.business_name
                AS seller_business_name

            FROM products p

            JOIN users u
              ON u.id = p.seller_id

            ORDER BY
              p.created_at DESC
          `
        );


      return res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Admin products error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load admin products"
      });

    }

  }
);


/* =========================================================
   ADMIN - SELLERS
========================================================= */

app.get(
  "/api/admin/sellers",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const result =
        await q(
          `
            SELECT
              id,
              name,
              email,
              business_name,
              gst_number,
              mobile,
              address,
              active,
              created_at

            FROM users

            WHERE role = 'seller'

            ORDER BY
              created_at DESC
          `
        );


      return res.json(
        result.rows.map(
          formatUser
        )
      );


    } catch (error) {

      console.error(
        "Admin sellers error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load sellers"
      });

    }

  }
);


/* =========================================================
   ADMIN - EDIT SELLER
========================================================= */

app.put(
  "/api/admin/sellers/:id",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const sellerId =
        Number(req.params.id);


      if (!Number.isInteger(sellerId)) {

        return res.status(400).json({
          error:
            "Invalid seller ID"
        });

      }


      const seller =
        await q(
          `
            SELECT *
            FROM users
            WHERE
              id = $1
              AND role = 'seller'
            LIMIT 1
          `,
          [sellerId]
        );


      if (!seller.rows.length) {

        return res.status(404).json({
          error:
            "Seller not found"
        });

      }


      const body =
        req.body || {};


      const name =
        clean(
          body.name ??
          seller.rows[0].name
        );

      const businessName =
        clean(
          body.businessName ??
          seller.rows[0].business_name
        );

      const gstNumber =
        clean(
          body.gstNumber ??
          seller.rows[0].gst_number
        ).toUpperCase();

      const mobile =
        clean(
          body.mobile ??
          seller.rows[0].mobile
        );

      const address =
        clean(
          body.address ??
          seller.rows[0].address
        );


      if (!name) {

        return res.status(400).json({
          error:
            "Name is required"
        });

      }


      if (
        gstNumber &&
        !isValidGST(gstNumber)
      ) {

        return res.status(400).json({
          error:
            "Invalid GSTIN format"
        });

      }


      if (
        mobile &&
        !isValidMobile(mobile)
      ) {

        return res.status(400).json({
          error:
            "Invalid mobile number"
        });

      }


      const duplicate =
        await q(
          `
            SELECT id
            FROM users
            WHERE
              gst_number = $1
              AND id <> $2
            LIMIT 1
          `,
          [
            gstNumber || null,
            sellerId
          ]
        );


      if (duplicate.rows.length) {

        return res.status(409).json({
          error:
            "GSTIN is already used by another seller"
        });

      }


      const result =
        await q(
          `
            UPDATE users

            SET
              name = $1,
              business_name = $2,
              gst_number = $3,
              mobile = $4,
              address = $5

            WHERE
              id = $6
              AND role = 'seller'

            RETURNING *
          `,
          [
            name,
            businessName || null,
            gstNumber || null,
            mobile || null,
            address || null,
            sellerId
          ]
        );


      return res.json({
        message:
          "Seller updated successfully",
        user:
          formatUser(
            result.rows[0]
          )
      });


    } catch (error) {

      console.error(
        "Edit seller error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to update seller"
      });

    }

  }
);


/* =========================================================
   ADMIN - SELLER ACTIVE / INACTIVE
========================================================= */

app.put(
  "/api/admin/sellers/:id/status",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const sellerId =
        Number(req.params.id);


      if (!Number.isInteger(sellerId)) {

        return res.status(400).json({
          error:
            "Invalid seller ID"
        });

      }


      const active =
        Boolean(
          req.body?.active
        );


      const result =
        await q(
          `
            UPDATE users

            SET active = $1

            WHERE
              id = $2
              AND role = 'seller'

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


      return res.json({
        message:
          active
            ? "Seller activated successfully"
            : "Seller deactivated successfully",

        user:
          formatUser(
            result.rows[0]
          )
      });


    } catch (error) {

      console.error(
        "Seller status error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to update seller status"
      });

    }

  }
);


/* =========================================================
   PUBLIC SELLERS
========================================================= */

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
              role = 'seller'
              AND active = TRUE

            ORDER BY
              created_at DESC
          `
        );


      return res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Public sellers error:",
        error
      );


      return res.status(500).json({
        error:
          "Unable to load sellers"
      });

    }

  }
);


/* =========================================================
   404
========================================================= */

app.use(
  (req, res) => {

    res.status(404).json({
      error:
        "API endpoint not found"
    });

  }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "Unhandled error:",
      error
    );


    if (
      error instanceof SyntaxError &&
      error.status === 400 &&
      error.body
    ) {

      return res.status(400).json({
        error:
          "Invalid JSON"
      });

    }


    return res.status(500).json({
      error:
        "Internal server error"
    });

  }
);


/* =========================================================
   START SERVER
========================================================= */

async function start() {

  try {

    await init();


    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `🚀 ShipNova API listening on port ${PORT}`
        );

      }
    );


  } catch (error) {

    console.error(
      "❌ Server startup failed:",
      error
    );

    process.exit(1);

  }

}


start();