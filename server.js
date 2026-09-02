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

const q = (text, params = []) => {
  return pool.query(text, params);
};


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
   USER FORMATTER
========================================= */

function formatUser(row) {

  return {

    id: row.id,

    name: row.name,

    email: row.email,

    role: row.role,

    active:
      row.active !== false,

    businessName:
      row.business_name || "",

    gstNumber:
      row.gst_number || "",

    mobile:
      row.mobile || "",

    address:
      row.address || "",

    created_at:
      row.created_at

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
     SELLER ACTIVE STATUS

     TRUE  = Active
     FALSE = Deactivated
  ======================================= */

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS active BOOLEAN
    NOT NULL DEFAULT TRUE
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
        role,
        active
      )

      VALUES(
        $1,
        $2,
        $3,
        'admin',
        TRUE
      )

      ON CONFLICT(email)

      DO UPDATE SET

        name = EXCLUDED.name,

        password = EXCLUDED.password,

        role = 'admin',

        active = TRUE
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
    version: "6.0"
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


        const gstRegex =
          /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;


        if (
          !gstRegex.test(cleanGstNumber)
        ) {

          return res.status(400).json({
            error:
              "Invalid GST Number format"
          });

        }


        if (
          !/^[6-9][0-9]{9}$/
            .test(cleanMobile)
        ) {

          return res.status(400).json({
            error:
              "Invalid mobile number"
          });

        }


        if (!cleanAddress) {

          return res.status(400).json({
            error:
              "Business address is required"
          });

        }


        const existingGST =
          await q(
            `
            SELECT id
            FROM users
            WHERE gst_number=$1
            `,
            [cleanGstNumber]
          );


        if (existingGST.rowCount) {

          return res.status(409).json({
            error:
              "GST Number already registered"
          });

        }

      }


      const existing =
        await q(
          `
          SELECT id
          FROM users
          WHERE email=$1
          `,
          [cleanEmail]
        );


      if (existing.rowCount) {

        return res.status(409).json({
          error:
            "Email already registered"
        });

      }


      const hash =
        await bcrypt.hash(
          cleanPassword,
          12
        );


      let result;


      if (cleanRole === "seller") {

        result =
          await q(
            `
            INSERT INTO users(

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

            VALUES(

              $1,
              $2,
              $3,
              'seller',

              $4,
              $5,
              $6,
              $7,
              TRUE

            )

            RETURNING *
            `,
            [
              cleanName,
              cleanEmail,
              hash,

              cleanBusinessName,
              cleanGstNumber,
              cleanMobile,
              cleanAddress
            ]
          );

      } else {

        result =
          await q(
            `
            INSERT INTO users(

              name,
              email,
              password,
              role,
              active

            )

            VALUES(

              $1,
              $2,
              $3,
              'customer',
              TRUE

            )

            RETURNING *
            `,
            [
              cleanName,
              cleanEmail,
              hash
            ]
          );

      }


      const row =
        result.rows[0];


      const user =
        formatUser(row);


      const token =
        tokenFor(user);


      res.status(201).json({
        ok: true,
        user,
        token
      });


    } catch (error) {

      console.error(
        "Registration error:",
        error
      );


      if (error.code === "23505") {

        return res.status(409).json({
          error:
            "Email or GST Number already registered"
        });

      }


      res.status(500).json({
        error:
          "Registration failed"
      });

    }

  }
);


/* =========================================
   LOGIN
========================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body || {};


      const cleanEmail =
        String(email || "")
          .trim()
          .toLowerCase();


      const cleanPassword =
        String(password || "");


      if (
        !cleanEmail ||
        !cleanPassword
      ) {

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
          `,
          [cleanEmail]
        );


      if (!result.rowCount) {

        return res.status(401).json({
          error:
            "Invalid email or password"
        });

      }


      const userRow =
        result.rows[0];


      const passwordOK =
        await bcrypt.compare(
          cleanPassword,
          userRow.password
        );


      if (!passwordOK) {

        return res.status(401).json({
          error:
            "Invalid email or password"
        });

      }


      /* =====================================
         INACTIVE SELLER CHECK
      ===================================== */

      if (
        userRow.role === "seller" &&
        userRow.active === false
      ) {

        return res.status(403).json({
          error:
            "Seller account is inactive. Please contact admin."
        });

      }


      if (
        userRow.role === "customer" &&
        userRow.active === false
      ) {

        return res.status(403).json({
          error:
            "Account is inactive. Please contact admin."
        });

      }


      const user =
        formatUser(userRow);


      const token =
        tokenFor(user);


      res.json({
        ok: true,
        user,
        token
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


/* =========================================
   CURRENT USER
========================================= */

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
          `,
          [req.user.id]
        );


      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "User not found"
        });

      }


      const row =
        result.rows[0];


      if (
        row.active === false
      ) {

        return res.status(403).json({
          error:
            "Account is inactive"
        });

      }


      res.json({
        user:
          formatUser(row)
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load account"
      });

    }

  }
);


/* =========================================
   PRODUCTS - PUBLIC
========================================= */

app.get(
  "/api/products",
  async (req, res) => {

    try {

      const values = [];

      let sql = `
        SELECT
          p.*,
          u.name AS seller_name,
          u.business_name AS seller_business_name
        FROM products p
        JOIN users u
          ON u.id=p.seller_id
        WHERE p.active=TRUE
          AND u.active=TRUE
      `;


      if (req.query.seller) {

        const sellerId =
          Number(req.query.seller);


        if (
          !Number.isInteger(sellerId)
        ) {

          return res.status(400).json({
            error:
              "Invalid seller"
          });

        }


        values.push(sellerId);


        sql += `
          AND p.seller_id=$${values.length}
        `;

      }


      if (req.query.q) {

        values.push(
          `%${String(
            req.query.q
          )}%`
        );


        sql += `
          AND (
            p.name ILIKE $${values.length}
            OR p.description ILIKE $${values.length}
          )
        `;

      }


      sql += `
        ORDER BY p.id DESC
      `;


      const result =
        await q(
          sql,
          values
        );


      res.json({
        products:
          result.rows
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load products"
      });

    }

  }
);


/* =========================================
   SINGLE PRODUCT
========================================= */

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
            u.business_name AS seller_business_name
          FROM products p
          JOIN users u
            ON u.id=p.seller_id
          WHERE p.id=$1
          `,
          [req.params.id]
        );


      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "Product not found"
        });

      }


      res.json({
        product:
          result.rows[0]
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load product"
      });

    }

  }
);


/* =========================================
   ADD PRODUCT
========================================= */

app.post(
  "/api/products",
  auth,
  role("seller", "admin"),
  async (req, res) => {

    try {

      const body =
        req.body || {};


      const name =
        String(body.name || "")
          .trim();


      const description =
        String(
          body.description || ""
        );


      const price =
        Number(body.price);


      const stock =
        Number(body.stock ?? 0);


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
            "Invalid price"
        });

      }


      if (
        !Number.isInteger(stock) ||
        stock < 0
      ) {

        return res.status(400).json({
          error:
            "Invalid stock"
        });

      }


      let sellerId =
        req.user.id;


      if (
        req.user.role === "admin" &&
        body.seller_id !== undefined
      ) {

        sellerId =
          Number(body.seller_id);

      }


      const seller =
        await q(
          `
          SELECT id
          FROM users
          WHERE id=$1
          AND role='seller'
          AND active=TRUE
          `,
          [sellerId]
        );


      if (!seller.rowCount) {

        return res.status(400).json({
          error:
            "Invalid or inactive seller"
        });

      }


      const result =
        await q(
          `
          INSERT INTO products(

            seller_id,
            name,
            description,
            price,
            stock,
            image,
            active

          )

          VALUES(

            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
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
            String(
              body.image || ""
            )
          ]
        );


      res.status(201).json({
        product:
          result.rows[0]
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not add product"
      });

    }

  }
);


/* =========================================
   UPDATE PRODUCT
========================================= */

app.put(
  "/api/products/:id",
  auth,
  role("seller", "admin"),
  async (req, res) => {

    try {

      const existing =
        await q(
          `
          SELECT *
          FROM products
          WHERE id=$1
          `,
          [req.params.id]
        );


      if (!existing.rowCount) {

        return res.status(404).json({
          error:
            "Product not found"
        });

      }


      const product =
        existing.rows[0];


      if (
        req.user.role === "seller" &&
        product.seller_id !== req.user.id
      ) {

        return res.status(403).json({
          error:
            "Not your product"
        });

      }


      const body =
        req.body || {};


      const name =
        body.name !== undefined
          ? String(body.name).trim()
          : product.name;


      const description =
        body.description !== undefined
          ? String(body.description)
          : product.description;


      const price =
        body.price !== undefined
          ? Number(body.price)
          : Number(product.price);


      const stock =
        body.stock !== undefined
          ? Number(body.stock)
          : Number(product.stock);


      const image =
        body.image !== undefined
          ? String(body.image)
          : product.image;


      const active =
        body.active !== undefined
          ? Boolean(body.active)
          : product.active;


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
            "Invalid price"
        });

      }


      if (
        !Number.isInteger(stock) ||
        stock < 0
      ) {

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
            description=$2,
            price=$3,
            stock=$4,
            image=$5,
            active=$6

          WHERE id=$7

          RETURNING *
          `,
          [
            name,
            description,
            price,
            stock,
            image,
            active,
            product.id
          ]
        );


      res.json({
        ok: true,
        product:
          result.rows[0]
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not update product"
      });

    }

  }
);


/* =========================================
   DELETE PRODUCT
========================================= */

app.delete(
  "/api/products/:id",
  auth,
  role("seller", "admin"),
  async (req, res) => {

    try {

      const existing =
        await q(
          `
          SELECT *
          FROM products
          WHERE id=$1
          `,
          [req.params.id]
        );


      if (!existing.rowCount) {

        return res.status(404).json({
          error:
            "Product not found"
        });

      }


      const product =
        existing.rows[0];


      if (
        req.user.role === "seller" &&
        product.seller_id !== req.user.id
      ) {

        return res.status(403).json({
          error:
            "Not your product"
        });

      }


      /*
       * Do not physically delete a product
       * if it already exists in an order.
       */

      const used =
        await q(
          `
          SELECT id
          FROM order_items
          WHERE product_id=$1
          LIMIT 1
          `,
          [product.id]
        );


      if (used.rowCount) {

        await q(
          `
          UPDATE products
          SET active=FALSE
          WHERE id=$1
          `,
          [product.id]
        );


        return res.json({
          ok: true,
          message:
            "Product has existing orders, so it was deactivated instead of deleted."
        });

      }


      await q(
        `
        DELETE FROM products
        WHERE id=$1
        `,
        [product.id]
      );


      res.json({
        ok: true
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not delete product"
      });

    }

  }
);


/* =========================================
   CUSTOMER - CREATE ORDER
========================================= */

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
            "Cart is empty"
        });

      }


      await client.query("BEGIN");


      let total = 0;

      const prepared = [];


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
            "Invalid product or quantity"
          );

        }


        const result =
          await client.query(
            `
            SELECT
              p.id,
              p.seller_id,
              p.name,
              p.price,
              p.stock,
              p.active,
              u.active AS seller_active
            FROM products p
            JOIN users u
              ON u.id=p.seller_id
            WHERE p.id=$1
            FOR UPDATE
            `,
            [productId]
          );


        if (!result.rowCount) {

          throw new Error(
            "Product not found"
          );

        }


        const product =
          result.rows[0];


        if (!product.active) {

          throw new Error(
            `${product.name} is unavailable`
          );

        }


        if (!product.seller_active) {

          throw new Error(
            `${product.name} seller is inactive`
          );

        }


        if (
          product.stock < quantity
        ) {

          throw new Error(
            `${product.name}: only ${product.stock} item(s) available`
          );

        }


        const price =
          Number(product.price);


        const subtotal =
          price * quantity;


        total += subtotal;


        prepared.push({
          product,
          quantity,
          price,
          subtotal
        });

      }


      const orderResult =
        await client.query(
          `
          INSERT INTO orders(
            customer_id,
            total,
            status
          )

          VALUES(
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
        const item of prepared
      ) {

        await client.query(
          `
          INSERT INTO order_items(

            order_id,
            product_id,
            seller_id,
            product_name,
            price,
            quantity,
            subtotal

          )

          VALUES(

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

          SET stock =
            stock - $1

          WHERE id=$2
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


    } catch (error) {

      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(
        "Order error:",
        error
      );


      res.status(400).json({
        error:
          error.message ||
          "Could not create order"
      });


    } finally {

      client.release();

    }

  }
);


/* =========================================
   CUSTOMER - MY ORDERS
========================================= */

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
              json_agg(
                json_build_object(

                  'id', oi.id,
                  'product_id', oi.product_id,
                  'product_name', oi.product_name,
                  'price', oi.price,
                  'quantity', oi.quantity,
                  'subtotal', oi.subtotal,
                  'seller_id', oi.seller_id

                )
                ORDER BY oi.id
              )
              FILTER(
                WHERE oi.id IS NOT NULL
              ),
              '[]'
            ) AS items

          FROM orders o

          LEFT JOIN order_items oi
            ON oi.order_id=o.id

          WHERE o.customer_id=$1

          GROUP BY o.id

          ORDER BY o.id DESC
          `,
          [req.user.id]
        );


      res.json({
        orders:
          result.rows
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load orders"
      });

    }

  }
);


/* =========================================
   SELLER - ORDERS
========================================= */

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

            u.name AS customer_name,

            u.email AS customer_email,

            o.total,

            o.status,

            o.created_at,

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

          WHERE oi.seller_id=$1

          ORDER BY
            o.id DESC,
            oi.id
          `,
          [req.user.id]
        );


      res.json({
        orders:
          result.rows
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load seller orders"
      });

    }

  }
);


/* =========================================
   ADMIN - ALL ORDERS
   Includes items
========================================= */

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

            COALESCE(
              json_agg(
                json_build_object(

                  'id', oi.id,

                  'product_id',
                  oi.product_id,

                  'product_name',
                  oi.product_name,

                  'seller_id',
                  oi.seller_id,

                  'seller_name',
                  seller.name,

                  'business_name',
                  seller.business_name,

                  'price',
                  oi.price,

                  'quantity',
                  oi.quantity,

                  'subtotal',
                  oi.subtotal

                )
                ORDER BY oi.id
              )
              FILTER(
                WHERE oi.id IS NOT NULL
              ),
              '[]'
            ) AS items

          FROM orders o

          JOIN users u
            ON u.id=o.customer_id

          LEFT JOIN order_items oi
            ON oi.order_id=o.id

          LEFT JOIN users seller
            ON seller.id=oi.seller_id

          GROUP BY
            o.id,
            u.id

          ORDER BY
            o.id DESC
          `
        );


      res.json({
        orders:
          result.rows
      });


    } catch (error) {

      console.error(
        "Admin orders error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load admin orders"
      });

    }

  }
);


/* =========================================
   ADMIN - SINGLE ORDER DETAILS
========================================= */

app.get(
  "/api/admin/orders/:id",
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
            u.address AS customer_address,

            COALESCE(
              json_agg(
                json_build_object(

                  'id', oi.id,

                  'product_id',
                  oi.product_id,

                  'product_name',
                  oi.product_name,

                  'seller_id',
                  oi.seller_id,

                  'seller_name',
                  seller.name,

                  'business_name',
                  seller.business_name,

                  'gst_number',
                  seller.gst_number,

                  'price',
                  oi.price,

                  'quantity',
                  oi.quantity,

                  'subtotal',
                  oi.subtotal

                )
                ORDER BY oi.id
              )
              FILTER(
                WHERE oi.id IS NOT NULL
              ),
              '[]'
            ) AS items

          FROM orders o

          JOIN users u
            ON u.id=o.customer_id

          LEFT JOIN order_items oi
            ON oi.order_id=o.id

          LEFT JOIN users seller
            ON seller.id=oi.seller_id

          WHERE o.id=$1

          GROUP BY
            o.id,
            u.id
          `,
          [req.params.id]
        );


      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "Order not found"
        });

      }


      res.json({
        order:
          result.rows[0]
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load order details"
      });

    }

  }
);


/* =========================================
   ADMIN - CHANGE ORDER STATUS
========================================= */

app.put(
  "/api/admin/orders/:id/status",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const allowed = [

        "pending",
        "confirmed",
        "shipped",
        "delivered",
        "cancelled"

      ];


      const status =
        String(
          req.body?.status || ""
        )
          .trim()
          .toLowerCase();


      if (
        !allowed.includes(status)
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
            req.params.id
          ]
        );


      if (!result.rowCount) {

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


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not update order"
      });

    }

  }
);


/* =========================================
   ADMIN - USERS
========================================= */

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
            active,

            business_name,
            gst_number,
            mobile,
            address,

            created_at

          FROM users

          ORDER BY id DESC
          `
        );


      res.json({
        users:
          result.rows.map(formatUser)
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load users"
      });

    }

  }
);


/* =========================================
   ADMIN - DASHBOARD STATS
========================================= */

app.get(
  "/api/stats",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const [

        users,
        customers,
        sellers,
        activeSellers,
        products,
        activeProducts,
        orders,
        revenue

      ] = await Promise.all([

        q(`
          SELECT COUNT(*)::int AS count
          FROM users
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE role='customer'
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE role='seller'
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM users
          WHERE role='seller'
          AND active=TRUE
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM products
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM products
          WHERE active=TRUE
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM orders
        `),

        q(`
          SELECT
            COALESCE(
              SUM(total),
              0
            )::numeric(14,2) AS revenue
          FROM orders
          WHERE status <> 'cancelled'
        `)

      ]);


      res.json({

        users:
          users.rows[0].count,

        customers:
          customers.rows[0].count,

        sellers:
          sellers.rows[0].count,

        activeSellers:
          activeSellers.rows[0].count,

        products:
          products.rows[0].count,

        activeProducts:
          activeProducts.rows[0].count,

        orders:
          orders.rows[0].count,

        revenue:
          Number(
            revenue.rows[0].revenue || 0
          )

      });


    } catch (error) {

      console.error(
        "Stats error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load statistics"
      });

    }

  }
);


/* =========================================
   ADMIN - ALL PRODUCTS
========================================= */

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

            p.id,
            p.seller_id,
            p.name,
            p.description,
            p.price,
            p.stock,
            p.image,
            p.active,
            p.created_at,

            seller.name AS seller_name,

            seller.business_name

          FROM products p

          JOIN users seller
            ON seller.id=p.seller_id

          ORDER BY
            p.id DESC
          `
        );


      res.json({
        products:
          result.rows
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load admin products"
      });

    }

  }
);


/* =========================================
   ADMIN - SELLERS
========================================= */

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
            active,

            business_name,
            gst_number,
            mobile,
            address,

            created_at

          FROM users

          WHERE role='seller'

          ORDER BY id DESC
          `
        );


      res.json({
        sellers:
          result.rows.map(formatUser)
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load sellers"
      });

    }

  }
);


/* =========================================
   ADMIN - EDIT SELLER
========================================= */

app.put(
  "/api/admin/sellers/:id",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const sellerId =
        Number(req.params.id);


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
          WHERE id=$1
          AND role='seller'
          `,
          [sellerId]
        );


      if (!existing.rowCount) {

        return res.status(404).json({
          error:
            "Seller not found"
        });

      }


      const current =
        existing.rows[0];


      const body =
        req.body || {};


      const name =
        body.name !== undefined
          ? String(body.name).trim()
          : current.name;


      const email =
        body.email !== undefined
          ? String(body.email)
              .trim()
              .toLowerCase()
          : current.email;


      const businessName =
        body.businessName !== undefined
          ? String(body.businessName).trim()
          : current.business_name;


      const gstNumber =
        body.gstNumber !== undefined
          ? String(body.gstNumber)
              .trim()
              .toUpperCase()
          : current.gst_number;


      const mobile =
        body.mobile !== undefined
          ? String(body.mobile)
              .replace(/\D/g, "")
          : current.mobile;


      const address =
        body.address !== undefined
          ? String(body.address).trim()
          : current.address;


      if (name.length < 2) {

        return res.status(400).json({
          error:
            "Invalid seller name"
        });

      }


      if (!email.includes("@")) {

        return res.status(400).json({
          error:
            "Invalid email"
        });

      }


      if (!businessName) {

        return res.status(400).json({
          error:
            "Business Name is required"
        });

      }


      const gstRegex =
        /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;


      if (
        !gstRegex.test(gstNumber)
      ) {

        return res.status(400).json({
          error:
            "Invalid GST Number format"
        });

      }


      if (
        !/^[6-9][0-9]{9}$/
          .test(mobile)
      ) {

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


      const duplicateEmail =
        await q(
          `
          SELECT id
          FROM users
          WHERE email=$1
          AND id<>$2
          `,
          [
            email,
            sellerId
          ]
        );


      if (duplicateEmail.rowCount) {

        return res.status(409).json({
          error:
            "Email already used"
        });

      }


      const duplicateGST =
        await q(
          `
          SELECT id
          FROM users
          WHERE gst_number=$1
          AND id<>$2
          `,
          [
            gstNumber,
            sellerId
          ]
        );


      if (duplicateGST.rowCount) {

        return res.status(409).json({
          error:
            "GST Number already used"
        });

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

          WHERE id=$7
          AND role='seller'

          RETURNING *
          `,
          [
            name,
            email,
            businessName,
            gstNumber,
            mobile,
            address,
            sellerId
          ]
        );


      res.json({
        ok: true,
        seller:
          formatUser(result.rows[0])
      });


    } catch (error) {

      console.error(
        "Seller update error:",
        error
      );


      if (error.code === "23505") {

        return res.status(409).json({
          error:
            "Email or GST Number already used"
        });

      }


      res.status(500).json({
        error:
          "Could not update seller"
      });

    }

  }
);


/* =========================================
   ADMIN - SELLER ACTIVE / INACTIVE
========================================= */

app.put(
  "/api/admin/sellers/:id/status",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const sellerId =
        Number(req.params.id);


      if (
        !Number.isInteger(sellerId)
      ) {

        return res.status(400).json({
          error:
            "Invalid seller ID"
        });

      }


      const active =
        req.body?.active;


      if (
        typeof active !== "boolean"
      ) {

        return res.status(400).json({
          error:
            "active must be true or false"
        });

      }


      const result =
        await q(
          `
          UPDATE users

          SET active=$1

          WHERE id=$2
          AND role='seller'

          RETURNING *
          `,
          [
            active,
            sellerId
          ]
        );


      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "Seller not found"
        });

      }


      /*
       * When seller becomes inactive,
       * their products are automatically
       * hidden from marketplace.
       *
       * When seller becomes active,
       * their products return according
       * to their own active flag.
       */

      if (!active) {

        await q(
          `
          UPDATE products

          SET active=FALSE

          WHERE seller_id=$1
          `,
          [sellerId]
        );

      }


      res.json({
        ok: true,

        seller:
          formatUser(result.rows[0])
      });


    } catch (error) {

      console.error(
        "Seller status error:",
        error
      );

      res.status(500).json({
        error:
          "Could not change seller status"
      });

    }

  }
);


/* =========================================
   PUBLIC SELLERS
========================================= */

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
            email,

            business_name,
            gst_number,
            mobile,
            address

          FROM users

          WHERE role='seller'
          AND active=TRUE

          ORDER BY name
          `
        );


      const sellers =
        result.rows.map(seller => ({

          id: seller.id,

          name: seller.name,

          email: seller.email,

          businessName:
            seller.business_name || "",

          gstNumber:
            seller.gst_number || "",

          mobile:
            seller.mobile || "",

          address:
            seller.address || ""

        }));


      res.json({
        sellers
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load sellers"
      });

    }

  }
);


/* =========================================
   404 API HANDLER
========================================= */

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


/* =========================================
   ERROR HANDLER
========================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "Unhandled server error:",
      error
    );


    if (res.headersSent) {
      return next(error);
    }


    res.status(500).json({
      error:
        "Server error"
    });

  }
);


/* =========================================
   START SERVER
========================================= */

async function start() {

  try {

    await init();

    await q("SELECT 1");


    app.listen(
      PORT,
      () => {

        console.log(
          `ShipNova API listening on port ${PORT}`
        );

      }
    );


  } catch (error) {

    console.error(
      "Startup failed:",
      error
    );


    process.exit(1);

  }

}


start();