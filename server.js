const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pg = require("pg");

const { Pool } = pg;

const app = express();

const PORT = process.env.PORT || 10000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret-in-render";

const ADMIN_EMAIL =
  process.env.ADMIN_EMAIL || "admin@shipnova.local";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "";


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: false
  })
);

app.use(
  express.json({
    limit: "10mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb"
  })
);


/* =========================================================
   DATABASE
========================================================= */

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not set.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    DATABASE_URL &&
    !DATABASE_URL.includes("localhost") &&
    !DATABASE_URL.includes("127.0.0.1")
      ? {
          rejectUnauthorized: false
        }
      : false
});


async function q(text, params = []) {
  return pool.query(text, params);
}


/* =========================================================
   HELPERS
========================================================= */

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

    businessName:
      row.business_name || "",

    gstNumber:
      row.gst_number || "",

    mobile:
      row.mobile || "",

    address:
      row.address || "",

    active:
      row.active !== false
  };
}


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
      jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}


function role(...roles) {
  return (req, res, next) => {
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


function cleanText(value, fallback = "") {
  return String(value ?? fallback).trim();
}


function numberValue(value, fallback = 0) {
  const n = Number(value);

  return Number.isFinite(n)
    ? n
    : fallback;
}


function positiveInteger(value) {
  const n = Number(value);

  if (!Number.isInteger(n) || n < 0) {
    return null;
  }

  return n;
}


/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function init() {

  console.log("Initializing database...");


  /* USERS */

  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer'
        CHECK (role IN ('customer','seller','admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      business_name TEXT,
      gst_number TEXT,
      mobile TEXT,
      address TEXT,

      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);


  /* Existing database migration */

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


  /* GST unique index */

  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    users_gst_number_unique
    ON users (gst_number)
    WHERE gst_number IS NOT NULL
      AND gst_number <> ''
  `);


  /* PRODUCTS */

  await q(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,

      seller_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      name TEXT NOT NULL,

      category TEXT NOT NULL DEFAULT 'Other',

      description TEXT,

      price NUMERIC(12,2) NOT NULL DEFAULT 0,

      stock INTEGER NOT NULL DEFAULT 0,

      image TEXT,

      active BOOLEAN NOT NULL DEFAULT TRUE,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /* Product migrations */

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS category TEXT
    NOT NULL DEFAULT 'Other'
  `);

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS description TEXT
  `);

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS price NUMERIC(12,2)
    NOT NULL DEFAULT 0
  `);

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS stock INTEGER
    NOT NULL DEFAULT 0
  `);

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS image TEXT
  `);

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS active BOOLEAN
    NOT NULL DEFAULT TRUE
  `);

  await q(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
    NOT NULL DEFAULT NOW()
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


  /* ORDERS */

  await q(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,

      customer_id INTEGER NOT NULL
        REFERENCES users(id),

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


  /* ORDER ITEMS */

  await q(`
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,

      order_id INTEGER NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,

      product_id INTEGER
        REFERENCES products(id)
        ON DELETE SET NULL,

      seller_id INTEGER
        REFERENCES users(id)
        ON DELETE SET NULL,

      product_name TEXT NOT NULL,

      price NUMERIC(12,2) NOT NULL,

      quantity INTEGER NOT NULL,

      subtotal NUMERIC(12,2) NOT NULL
    )
  `);


  /* ADMIN ACCOUNT */

  if (ADMIN_PASSWORD) {

    const hashedPassword =
      await bcrypt.hash(
        ADMIN_PASSWORD,
        10
      );

    const existing =
      await q(
        `
        SELECT id
        FROM users
        WHERE LOWER(email) = LOWER($1)
          AND role = 'admin'
        LIMIT 1
        `,
        [ADMIN_EMAIL]
      );


    if (existing.rows.length) {

      await q(
        `
        UPDATE users
        SET
          name = $1,
          password = $2,
          active = TRUE
        WHERE id = $3
        `,
        [
          "ShipNova Administrator",
          hashedPassword,
          existing.rows[0].id
        ]
      );

      console.log(
        "Admin account updated:",
        ADMIN_EMAIL
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
          "ShipNova Administrator",
          ADMIN_EMAIL,
          hashedPassword
        ]
      );

      console.log(
        "Admin account created:",
        ADMIN_EMAIL
      );
    }

  } else {

    console.warn(
      "ADMIN_PASSWORD is not set. Admin account was not created/updated."
    );
  }


  console.log(
    "Database initialization complete."
  );
}


/* =========================================================
   HEALTH
========================================================= */

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

      console.error(
        "Health check failed:",
        error
      );

      res.status(500).json({
        ok: false,
        database: "disconnected"
      });
    }
  }
);


/* =========================================================
   AUTH - REGISTER
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const body =
        req.body || {};

      const name =
        cleanText(body.name);

      const email =
        cleanText(body.email).toLowerCase();

      const password =
        String(body.password || "");

      const roleName =
        cleanText(
          body.role,
          "customer"
        ).toLowerCase();


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
          roleName
        )
      ) {
        return res.status(400).json({
          error: "Invalid registration role"
        });
      }


      /* Seller fields */

      let businessName = null;
      let gstNumber = null;
      let mobile = null;
      let address = null;


      if (roleName === "seller") {

        businessName =
          cleanText(
            body.businessName ||
            body.business_name
          );

        gstNumber =
          cleanText(
            body.gstNumber ||
            body.gst_number
          ).toUpperCase();

        mobile =
          cleanText(body.mobile);

        address =
          cleanText(body.address);


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


        if (!gstRegex.test(gstNumber)) {
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


        const mobileRegex =
          /^[6-9][0-9]{9}$/;


        if (!mobileRegex.test(mobile)) {
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


      /* Existing email */

      const existingEmail =
        await q(
          `
          SELECT id
          FROM users
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1
          `,
          [email]
        );


      if (existingEmail.rows.length) {
        return res.status(409).json({
          error:
            "Email already registered"
        });
      }


      /* Existing GST */

      if (gstNumber) {

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
              "GST number already registered"
          });
        }
      }


      const hashedPassword =
        await bcrypt.hash(
          password,
          10
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
          RETURNING
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
          `,
          [
            name,
            email,
            hashedPassword,
            roleName,
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


      res.status(201).json({
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

      res.status(500).json({
        error:
          "Registration failed"
      });
    }
  }
);


/* =========================================================
   AUTH - LOGIN
========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const email =
        cleanText(
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


      const passwordOK =
        await bcrypt.compare(
          password,
          userRow.password
        );


      if (!passwordOK) {
        return res.status(401).json({
          error:
            "Invalid email or password"
        });
      }


      if (userRow.active === false) {
        return res.status(403).json({
          error:
            "Your account is inactive. Please contact admin."
        });
      }


      const token =
        tokenFor(
          userRow
        );


      res.json({
        message:
          "Login successful",
        token,
        user:
          formatUser(userRow)
      });


    } catch (error) {

      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error:
          "Login failed"
      });
    }
  }
);


/* =========================================================
   AUTH - CURRENT USER
========================================================= */

app.get(
  "/api/auth/me",
  auth,
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


      res.json({
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

      res.status(500).json({
        error:
          "Unable to load user"
      });
    }
  }
);


/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  "/api/products",
  async (req, res) => {

    try {

      const seller =
        req.query.seller;

      const search =
        cleanText(
          req.query.q
        );

      const category =
        cleanText(
          req.query.category
        );


      let sql = `
        SELECT
          p.*,

          u.name AS seller_name,

          u.business_name
            AS seller_business_name

        FROM products p

        JOIN users u
          ON u.id = p.seller_id

        WHERE
          p.active = TRUE

          AND u.active = TRUE
      `;


      const params = [];


      if (seller) {

        params.push(
          seller
        );

        sql += `
          AND p.seller_id = $${params.length}
        `;
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

        params.push(
          category
        );

        sql += `
          AND LOWER(p.category)
            = LOWER($${params.length})
        `;
      }


      sql += `
        ORDER BY
          p.created_at DESC,
          p.id DESC
      `;


      const result =
        await q(
          sql,
          params
        );


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Products error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load products"
      });
    }
  }
);


/* =========================================================
   SINGLE PRODUCT
========================================================= */

app.get(
  "/api/products/:id",
  async (req, res) => {

    try {

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
          [req.params.id]
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


    } catch (error) {

      console.error(
        "Product detail error:",
        error
      );

      res.status(500).json({
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
        cleanText(
          body.name
        );

      const category =
        cleanText(
          body.category,
          "Other"
        ) || "Other";

      const description =
        cleanText(
          body.description
        );

      const price =
        numberValue(
          body.price,
          NaN
        );

      const stock =
        positiveInteger(
          body.stock
        );

      const image =
        cleanText(
          body.image
        );


      if (!name) {
        return res.status(400).json({
          error:
            "Product name is required"
        });
      }


      if (!Number.isFinite(price) || price < 0) {
        return res.status(400).json({
          error:
            "Invalid product price"
        });
      }


      if (stock === null) {
        return res.status(400).json({
          error:
            "Invalid stock quantity"
        });
      }


      let sellerId =
        req.user.id;


      /* Admin can optionally supply seller_id */

      if (
        req.user.role === "admin" &&
        body.seller_id
      ) {

        sellerId =
          Number(body.seller_id);
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
        return res.status(400).json({
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
            sellerId,
            name,
            category,
            description,
            price,
            stock,
            image
          ]
        );


      res.status(201).json({
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

      res.status(500).json({
        error:
          "Unable to add product"
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

      const productId =
        Number(
          req.params.id
        );


      if (!Number.isInteger(productId)) {
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
        String(product.seller_id) !==
          String(req.user.id)
      ) {
        return res.status(403).json({
          error:
            "You can only edit your own products"
        });
      }


      const body =
        req.body || {};


      const name =
        cleanText(
          body.name,
          product.name
        );


      const category =
        cleanText(
          body.category,
          product.category || "Other"
        ) || "Other";


      const description =
        body.description !== undefined
          ? cleanText(body.description)
          : product.description || "";


      const price =
        body.price !== undefined
          ? numberValue(body.price, NaN)
          : Number(product.price);


      const stock =
        body.stock !== undefined
          ? positiveInteger(body.stock)
          : Number(product.stock);


      const image =
        body.image !== undefined
          ? cleanText(body.image)
          : product.image || "";


      let active =
        product.active;


      if (
        body.active !== undefined
      ) {

        active =
          Boolean(
            body.active
          );
      }


      if (!name) {
        return res.status(400).json({
          error:
            "Product name is required"
        });
      }


      if (!Number.isFinite(price) || price < 0) {
        return res.status(400).json({
          error:
            "Invalid product price"
        });
      }


      if (stock === null) {
        return res.status(400).json({
          error:
            "Invalid stock quantity"
        });
      }


      const result =
        await q(
          `
          UPDATE products

          SET
            name = $1,
            category = $2,
            description = $3,
            price = $4,
            stock = $5,
            image = $6,
            active = $7

          WHERE id = $8

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

      res.status(500).json({
        error:
          "Unable to update product"
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

      const productId =
        Number(
          req.params.id
        );


      const existing =
        await q(
          `
          SELECT *
          FROM products
          WHERE id = $1
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
        String(product.seller_id) !==
          String(req.user.id)
      ) {
        return res.status(403).json({
          error:
            "You can only delete your own products"
        });
      }


      /*
        If product has order history,
        deactivate instead of deleting.
      */

      const orderCheck =
        await q(
          `
          SELECT id
          FROM order_items
          WHERE product_id = $1
          LIMIT 1
          `,
          [productId]
        );


      if (orderCheck.rows.length) {

        await q(
          `
          UPDATE products
          SET active = FALSE
          WHERE id = $1
          `,
          [productId]
        );


        return res.json({
          message:
            "Product deactivated because it has order history."
        });
      }


      await q(
        `
        DELETE FROM products
        WHERE id = $1
        `,
        [productId]
      );


      res.json({
        message:
          "Product deleted successfully."
      });


    } catch (error) {

      console.error(
        "Delete product error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to delete product"
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

      const preparedItems = [];


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
          productId <= 0
        ) {

          throw new Error(
            "Invalid product ID"
          );
        }


        if (
          !Number.isInteger(quantity) ||
          quantity <= 0
        ) {

          throw new Error(
            "Invalid product quantity"
          );
        }


        const result =
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


        if (!result.rows.length) {

          throw new Error(
            "Product not found"
          );
        }


        const product =
          result.rows[0];


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


        total +=
          subtotal;


        preparedItems.push({
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


      for (
        const item
        of preparedItems
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


      await client.query(
        "COMMIT"
      );


      res.status(201).json({
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


      res.status(400).json({
        error:
          error.message ||
          "Unable to place order"
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


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Customer orders error:",
        error
      );

      res.status(500).json({
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
            o.id AS order_id,

            o.customer_id,

            o.total,

            o.status,

            o.created_at,

            u.name
              AS customer_name,

            u.email
              AS customer_email,

            u.mobile
              AS customer_mobile,

            u.address
              AS customer_address,

            oi.id
              AS item_id,

            oi.product_id,

            oi.product_name,

            oi.price,

            oi.quantity,

            oi.subtotal

          FROM orders o

          JOIN order_items oi
            ON oi.order_id = o.id

          JOIN users u
            ON u.id = o.customer_id

          WHERE
            oi.seller_id = $1

          ORDER BY
            o.created_at DESC,
            o.id DESC
          `,
          [req.user.id]
        );


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Seller orders error:",
        error
      );

      res.status(500).json({
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

            u.name
              AS customer_name,

            u.email
              AS customer_email,

            u.mobile
              AS customer_mobile

          FROM orders o

          JOIN users u
            ON u.id = o.customer_id

          ORDER BY
            o.created_at DESC,
            o.id DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Admin orders error:",
        error
      );

      res.status(500).json({
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
        Number(
          req.params.id
        );


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

            s.name
              AS seller_name,

            s.business_name
              AS seller_business_name

          FROM order_items oi

          LEFT JOIN users s
            ON s.id = oi.seller_id

          WHERE
            oi.order_id = $1

          ORDER BY
            oi.id ASC
          `,
          [orderId]
        );


      res.json({
        order:
          orderResult.rows[0],

        items:
          itemsResult.rows
      });


    } catch (error) {

      console.error(
        "Admin order detail error:",
        error
      );

      res.status(500).json({
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
        Number(
          req.params.id
        );

      const status =
        cleanText(
          req.body?.status
        ).toLowerCase();


      const validStatuses = [
        "pending",
        "confirmed",
        "shipped",
        "delivered",
        "cancelled"
      ];


      if (
        !validStatuses.includes(
          status
        )
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


      res.json({
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

      res.status(500).json({
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
            created_at,
            business_name,
            gst_number,
            mobile,
            address,
            active

          FROM users

          ORDER BY
            created_at DESC,
            id DESC
          `
        );


      res.json(
        result.rows.map(
          formatUser
        )
      );


    } catch (error) {

      console.error(
        "Users error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load users"
      });
    }
  }
);


/* =========================================================
   ADMIN - STATS
========================================================= */

app.get(
  "/api/stats",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const result =
        await q(`
          SELECT

            (
              SELECT COUNT(*)
              FROM users
            ) AS users,

            (
              SELECT COUNT(*)
              FROM users
              WHERE role = 'customer'
            ) AS customers,

            (
              SELECT COUNT(*)
              FROM users
              WHERE role = 'seller'
            ) AS sellers,

            (
              SELECT COUNT(*)
              FROM users
              WHERE role = 'seller'
                AND active = TRUE
            ) AS active_sellers,

            (
              SELECT COUNT(*)
              FROM products
            ) AS products,

            (
              SELECT COUNT(*)
              FROM orders
            ) AS orders,

            (
              SELECT COALESCE(
                SUM(total),
                0
              )
              FROM orders
              WHERE status <> 'cancelled'
            ) AS revenue
        `);


      const row =
        result.rows[0];


      res.json({
        users:
          Number(row.users || 0),

        customers:
          Number(row.customers || 0),

        sellers:
          Number(row.sellers || 0),

        active_sellers:
          Number(row.active_sellers || 0),

        products:
          Number(row.products || 0),

        orders:
          Number(row.orders || 0),

        revenue:
          Number(row.revenue || 0)
      });


    } catch (error) {

      console.error(
        "Stats error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load statistics"
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

            u.name
              AS seller_name,

            u.email
              AS seller_email,

            u.business_name
              AS seller_business_name

          FROM products p

          LEFT JOIN users u
            ON u.id = p.seller_id

          ORDER BY
            p.created_at DESC,
            p.id DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Admin products error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load products"
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
            u.id,
            u.name,
            u.email,
            u.business_name,
            u.gst_number,
            u.mobile,
            u.address,
            u.active,
            u.created_at,

            COUNT(p.id)
              AS product_count

          FROM users u

          LEFT JOIN products p
            ON p.seller_id = u.id

          WHERE
            u.role = 'seller'

          GROUP BY
            u.id

          ORDER BY
            u.created_at DESC
          `
        );


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Admin sellers error:",
        error
      );

      res.status(500).json({
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
        Number(
          req.params.id
        );


      const body =
        req.body || {};


      const name =
        cleanText(
          body.name
        );

      const email =
        cleanText(
          body.email
        ).toLowerCase();

      const businessName =
        cleanText(
          body.businessName ||
          body.business_name
        );

      const gstNumber =
        cleanText(
          body.gstNumber ||
          body.gst_number
        ).toUpperCase();

      const mobile =
        cleanText(
          body.mobile
        );

      const address =
        cleanText(
          body.address
        );


      if (!name || !email) {
        return res.status(400).json({
          error:
            "Name and email are required"
        });
      }


      if (gstNumber) {

        const gstRegex =
          /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;


        if (!gstRegex.test(gstNumber)) {
          return res.status(400).json({
            error:
              "Invalid GSTIN format"
          });
        }
      }


      if (mobile) {

        const mobileRegex =
          /^[6-9][0-9]{9}$/;


        if (!mobileRegex.test(mobile)) {
          return res.status(400).json({
            error:
              "Invalid mobile number"
          });
        }
      }


      const result =
        await q(
          `
          UPDATE users

          SET
            name = $1,
            email = $2,
            business_name = $3,
            gst_number = $4,
            mobile = $5,
            address = $6

          WHERE
            id = $7

            AND role = 'seller'

          RETURNING
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


      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Seller not found"
        });
      }


      res.json({
        message:
          "Seller updated successfully",

        seller:
          formatUser(
            result.rows[0]
          )
      });


    } catch (error) {

      console.error(
        "Edit seller error:",
        error
      );


      if (
        error.code === "23505"
      ) {
        return res.status(409).json({
          error:
            "Email or GST number already exists"
        });
      }


      res.status(500).json({
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
        Number(
          req.params.id
        );


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

          RETURNING
            id,
            name,
            email,
            role,
            active
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


      /*
        When seller is deactivated,
        their products are hidden from
        public marketplace.

        We don't permanently delete them.
      */

      res.json({
        message:
          active
            ? "Seller activated successfully"
            : "Seller deactivated successfully",

        seller:
          result.rows[0]
      });


    } catch (error) {

      console.error(
        "Seller status error:",
        error
      );

      res.status(500).json({
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


      res.json(
        result.rows
      );


    } catch (error) {

      console.error(
        "Public sellers error:",
        error
      );

      res.status(500).json({
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
        "API endpoint not found",
      path:
        req.originalUrl
    });
  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(
      "Unhandled server error:",
      err
    );


    res.status(500).json({
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
          `ShipNova API listening on port ${PORT}`
        );

        console.log(
          `Health: /api/health`
        );
      }
    );


  } catch (error) {

    console.error(
      "Server startup failed:",
      error
    );

    process.exit(1);
  }
}


start();