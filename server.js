import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

const { Pool } = pg;

const app = express();

const PORT = Number(process.env.PORT || 10000);

const JWT_SECRET =
  process.env.JWT_SECRET;

const DATABASE_URL =
  process.env.DATABASE_URL;


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
    throw new Error(
      "JWT_SECRET is not configured"
    );
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

    req.user =
      jwt.verify(
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

    if (
      allowedRoles.includes(userRole)
    ) {

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


  /*
   * USERS
   */

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


  /*
   * PRODUCTS
   */

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


  /*
   * ORDERS
   */

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


  /*
   * ORDER ITEMS
   */

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


  /*
   * ADMIN ACCOUNT
   *
   * Set ADMIN_EMAIL and
   * ADMIN_PASSWORD in Render.
   */

  const adminEmail =
    String(
      process.env.ADMIN_EMAIL ||
      "admin@shipnova.local"
    )
      .trim()
      .toLowerCase();


  const adminPassword =
    String(
      process.env.ADMIN_PASSWORD ||
      ""
    );


  /*
   * We don't silently create an
   * insecure default admin password.
   */

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
    version: "4.0"
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
        role: requestedRole = "customer"
      } = req.body || {};


      if (
        !name ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          error:
            "name, email and password are required"
        });

      }


      /*
       * Public registration can create
       * customer or seller only.
       *
       * Admin cannot be created publicly.
       */

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


      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();


      const cleanName =
        String(name)
          .trim();


      if (cleanName.length < 2) {

        return res.status(400).json({
          error:
            "Name must contain at least 2 characters"
        });

      }


      if (
        String(password).length < 6
      ) {

        return res.status(400).json({
          error:
            "Password must contain at least 6 characters"
        });

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
          String(password),
          12
        );


      const result =
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
            $4
          )

          RETURNING
            id,
            name,
            email,
            role
          `,
          [
            cleanName,
            cleanEmail,
            hash,
            cleanRole
          ]
        );


      const user =
        result.rows[0];


      const token =
        tokenFor(user);


      res.status(201).json({
        user,
        token
      });


    } catch (error) {

      console.error(
        "Registration error:",
        error
      );


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
          SELECT
            id,
            name,
            email,
            password,
            role
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


      const user = {

        id: userRow.id,

        name: userRow.name,

        email: userRow.email,

        role: userRow.role

      };


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
          SELECT
            id,
            name,
            email,
            role,
            created_at
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


      res.json({
        user: result.rows[0]
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
          u.name AS seller_name
        FROM products p

        JOIN users u
          ON u.id=p.seller_id

        WHERE p.active=TRUE
      `;


      if (req.query.seller) {

        const sellerId =
          Number(req.query.seller);


        if (
          !Number.isInteger(
            sellerId
          )
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
            u.name AS seller_name
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
        Number(body.stock || 0);


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
          AND role IN(
            'seller',
            'admin'
          )
          `,
          [sellerId]
        );


      if (!seller.rowCount) {

        return res.status(400).json({
          error:
            "Invalid seller_id"
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


      await client.query(
        "BEGIN"
      );


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
          !Number.isInteger(
            productId
          ) ||
          !Number.isInteger(
            quantity
          ) ||
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
              id,
              seller_id,
              name,
              price,
              stock,
              active

            FROM products

            WHERE id=$1

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


        if (
          product.stock <
          quantity
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


      await client.query(
        "COMMIT"
      );


      res.status(201).json({
        order
      });


    } catch (error) {

      await client.query(
        "ROLLBACK"
      );


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
   ADMIN - ORDERS
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

            o.total,

            o.status,

            o.created_at,

            u.name AS customer_name,

            u.email AS customer_email

          FROM orders o

          JOIN users u
            ON u.id=o.customer_id

          ORDER BY
            o.id DESC
          `
        );


      res.json({
        orders:
          result.rows
      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load admin orders"
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
            created_at

          FROM users

          ORDER BY id DESC
          `
        );


      res.json({
        users:
          result.rows
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
   ADMIN - STATS
========================================= */

app.get(
  "/api/stats",
  auth,
  role("admin"),
  async (req, res) => {

    try {

      const [
        customers,
        sellers,
        products,
        orders
      ] = await Promise.all([

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
          FROM products
        `),

        q(`
          SELECT COUNT(*)::int AS count
          FROM orders
        `)

      ]);


      res.json({

        customers:
          customers.rows[0].count,

        sellers:
          sellers.rows[0].count,

        products:
          products.rows[0].count,

        orders:
          orders.rows[0].count

      });


    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load statistics"
      });

    }

  }
);


/* =========================================
   SELLERS - PUBLIC
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
            email

          FROM users

          WHERE role='seller'

          ORDER BY name
          `
        );


      res.json({
        sellers:
          result.rows
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