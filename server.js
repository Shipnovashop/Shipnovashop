import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const { Pool } = pg;
const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-render';

const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl: process.env.DATABASE_URL?.includes('localhost')
? false
: { rejectUnauthorized: false }
});

app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: '1mb' }));

const q = (text, params = []) => pool.query(text, params);

const tokenFor = u =>
jwt.sign(
{
id: u.id,
name: u.name,
email: u.email,
role: u.role
},
JWT_SECRET,
{ expiresIn: '7d' }
);

function auth(req, res, next) {
const h = req.headers.authorization || '';

if (!h.startsWith('Bearer ')) {
return res.status(401).json({ error: 'Login required' });
}

try {
req.user = jwt.verify(h.slice(7), JWT_SECRET);
next();
} catch {
return res.status(401).json({
error: 'Invalid or expired login'
});
}
}

function role(...roles) {
return (req, res, next) =>
roles.includes(req.user?.role)
? next()
: res.status(403).json({
error: 'Permission denied'
});
}

/* =========================
DATABASE INIT
========================= */

async function init() {

if (!process.env.DATABASE_URL) {
throw new Error('DATABASE_URL is required');
}

await q("CREATE TABLE IF NOT EXISTS users ( id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','seller','admin')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW() )");

await q("CREATE TABLE IF NOT EXISTS products ( id SERIAL PRIMARY KEY, seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', price NUMERIC(12,2) NOT NULL DEFAULT 0, stock INTEGER NOT NULL DEFAULT 0, image TEXT NOT NULL DEFAULT '', active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW() )");

await q("CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id)");

/* ORDERS */

await q("CREATE TABLE IF NOT EXISTS orders ( id SERIAL PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, total NUMERIC(12,2) NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ( 'pending', 'confirmed', 'shipped', 'delivered', 'cancelled' )), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW() )");

await q("CREATE TABLE IF NOT EXISTS order_items ( id SERIAL PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT, seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT, product_name TEXT NOT NULL, price NUMERIC(12,2) NOT NULL, quantity INTEGER NOT NULL, subtotal NUMERIC(12,2) NOT NULL )");

await q("CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id)");

await q("CREATE INDEX IF NOT EXISTS idx_order_items_seller ON order_items(seller_id)");

/* ADMIN */

const email =
(process.env.ADMIN_EMAIL || 'admin@shipnova.local')
.toLowerCase();

const password =
process.env.ADMIN_PASSWORD || 'admin123';

const hash = await bcrypt.hash(password, 12);

await q(
"INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,'admin') ON CONFLICT(email) DO UPDATE SET role='admin'",
['Administrator', email, hash]
);
}

/* =========================
BASIC
========================= */

app.get('/', (req, res) => {
res.json({
ok: true,
name: 'ShipNova API',
version: '3.0'
});
});

app.get('/api/health', async (req, res) => {

try {

await q('SELECT 1');

res.json({
  ok: true,
  database: 'connected'
});

} catch (e) {

res.status(503).json({
  ok: false,
  error: 'Database unavailable'
});

}

});

/* =========================
AUTH
========================= */

app.post('/api/auth/register', async (req, res) => {

try {

const {
  name,
  email,
  password,
  role: requestedRole = 'customer'
} = req.body || {};

if (!name || !email || !password) {
  return res.status(400).json({
    error: 'name, email and password are required'
  });
}

if (!['customer', 'seller'].includes(requestedRole)) {
  return res.status(400).json({
    error: 'Invalid role'
  });
}

const em = String(email).trim().toLowerCase();

const exists = await q(
  'SELECT id FROM users WHERE email=$1',
  [em]
);

if (exists.rowCount) {
  return res.status(409).json({
    error: 'Email already registered'
  });
}

const hash = await bcrypt.hash(
  String(password),
  12
);

const r = await q(
  `
  INSERT INTO users(name,email,password,role)
  VALUES($1,$2,$3,$4)
  RETURNING id,name,email,role
  `,
  [
    String(name).trim(),
    em,
    hash,
    requestedRole
  ]
);

const u = r.rows[0];

res.status(201).json({
  user: u,
  token: tokenFor(u)
});

} catch (e) {

console.error(e);

res.status(500).json({
  error: 'Registration failed'
});

}

});

app.post('/api/auth/login', async (req, res) => {

try {

const {
  email,
  password
} = req.body || {};

const em =
  String(email || '')
    .trim()
    .toLowerCase();

const r = await q(
  `
  SELECT id,name,email,password,role
  FROM users
  WHERE email=$1
  `,
  [em]
);

if (
  !r.rowCount ||
  !(await bcrypt.compare(
    String(password || ''),
    r.rows[0].password
  ))
) {

  return res.status(401).json({
    error: 'Invalid email or password'
  });

}

const {
  password: _,
  ...u
} = r.rows[0];

res.json({
  user: u,
  token: tokenFor(u)
});

} catch (e) {

console.error(e);

res.status(500).json({
  error: 'Login failed'
});

}

});

/* =========================
PRODUCTS
========================= */

app.get('/api/products', async (req, res) => {

try {

const vals = [];

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

  vals.push(Number(req.query.seller));

  sql += `
    AND p.seller_id=$${vals.length}
  `;

}

if (req.query.q) {

  vals.push(
    '%' + String(req.query.q) + '%'
  );

  sql += `
    AND (
      p.name ILIKE $${vals.length}
      OR p.description ILIKE $${vals.length}
    )
  `;

}

sql += ' ORDER BY p.id DESC';

const r = await q(sql, vals);

res.json({
  products: r.rows
});

} catch (e) {

console.error(e);

res.status(500).json({
  error: 'Could not load products'
});

}

});

app.get('/api/products/:id', async (req, res) => {

try {

const r = await q(
  `
  SELECT
    p.*,
    u.name seller_name
  FROM products p
  JOIN users u
    ON u.id=p.seller_id
  WHERE p.id=$1
  `,
  [req.params.id]
);

if (!r.rowCount) {

  return res.status(404).json({
    error: 'Product not found'
  });

}

res.json({
  product: r.rows[0]
});

} catch (e) {

res.status(500).json({
  error: 'Could not load product'
});

}

});

/* ADD PRODUCT */

app.post(
'/api/products',
auth,
role('seller', 'admin'),
async (req, res) => {

try {

  const b = req.body || {};

  if (!b.name || b.price === undefined) {

    return res.status(400).json({
      error: 'name and price are required'
    });

  }

  const sellerId =
    req.user.role === 'admin' && b.seller_id
      ? Number(b.seller_id)
      : req.user.id;

  const s = await q(
    `
    SELECT id
    FROM users
    WHERE id=$1
    AND role IN ('seller','admin')
    `,
    [sellerId]
  );

  if (!s.rowCount) {

    return res.status(400).json({
      error: 'Invalid seller_id'
    });

  }

  const r = await q(
    `
    INSERT INTO products
    (
      seller_id,
      name,
      description,
      price,
      stock,
      image,
      active
    )
    VALUES($1,$2,$3,$4,$5,$6,TRUE)
    RETURNING *
    `,
    [
      sellerId,
      String(b.name).trim(),
      b.description || '',
      Number(b.price),
      Number(b.stock || 0),
      b.image || ''
    ]
  );

  res.status(201).json({
    product: r.rows[0]
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not add product'
  });

}

}
);

/* UPDATE PRODUCT */

app.put(
'/api/products/:id',
auth,
role('seller', 'admin'),
async (req, res) => {

try {

  const r = await q(
    'SELECT * FROM products WHERE id=$1',
    [req.params.id]
  );

  if (!r.rowCount) {

    return res.status(404).json({
      error: 'Product not found'
    });

  }

  const p = r.rows[0];

  if (
    req.user.role === 'seller' &&
    p.seller_id !== req.user.id
  ) {

    return res.status(403).json({
      error: 'Not your product'
    });

  }

  const b = req.body || {};

  const x = await q(
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
      b.name ?? p.name,
      b.description ?? p.description,
      Number(b.price ?? p.price),
      Number(b.stock ?? p.stock),
      b.image ?? p.image,
      b.active === undefined
        ? p.active
        : Boolean(b.active),
      p.id
    ]
  );

  res.json({
    product: x.rows[0]
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not update product'
  });

}

}
);

/* DELETE PRODUCT */

app.delete(
'/api/products/:id',
auth,
role('seller', 'admin'),
async (req, res) => {

try {

  const r = await q(
    'SELECT * FROM products WHERE id=$1',
    [req.params.id]
  );

  if (!r.rowCount) {

    return res.status(404).json({
      error: 'Product not found'
    });

  }

  if (
    req.user.role === 'seller' &&
    r.rows[0].seller_id !== req.user.id
  ) {

    return res.status(403).json({
      error: 'Not your product'
    });

  }

  await q(
    'DELETE FROM products WHERE id=$1',
    [req.params.id]
  );

  res.json({
    ok: true
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not delete product'
  });

}

}
);

/* =========================
CUSTOMER ORDERS
========================= */

/* PLACE ORDER */

app.post(
'/api/orders',
auth,
role('customer'),
async (req, res) => {

const client = await pool.connect();

try {

  const items = Array.isArray(req.body?.items)
    ? req.body.items
    : [];

  if (!items.length) {

    return res.status(400).json({
      error: 'Cart is empty'
    });

  }

  await client.query('BEGIN');

  let total = 0;

  const prepared = [];

  for (const item of items) {

    const productId =
      Number(item.product_id);

    const quantity =
      Number(item.quantity);

    if (
      !productId ||
      !Number.isInteger(quantity) ||
      quantity <= 0
    ) {

      throw new Error(
        'Invalid product or quantity'
      );

    }

    const r = await client.query(
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

    if (!r.rowCount) {
      throw new Error(
        'Product not found'
      );
    }

    const p = r.rows[0];

    if (!p.active) {
      throw new Error(
        `${p.name} is unavailable`
      );
    }

    if (p.stock < quantity) {
      throw new Error(
        `${p.name}: only ${p.stock} item(s) available`
      );
    }

    const price = Number(p.price);

    const subtotal =
      price * quantity;

    total += subtotal;

    prepared.push({
      product: p,
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
      VALUES($1,$2,'pending')
      RETURNING *
      `,
      [
        req.user.id,
        total
      ]
    );

  const order =
    orderResult.rows[0];

  for (const item of prepared) {

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
      VALUES($1,$2,$3,$4,$5,$6,$7)
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
      SET stock=stock-$1
      WHERE id=$2
      `,
      [
        item.quantity,
        item.product.id
      ]
    );

  }

  await client.query('COMMIT');

  res.status(201).json({
    order
  });

} catch (e) {

  await client.query('ROLLBACK');

  console.error(e);

  res.status(400).json({
    error:
      e.message ||
      'Could not create order'
  });

} finally {

  client.release();

}

}
);

/* CUSTOMER MY ORDERS */

app.get(
'/api/orders',
auth,
role('customer'),
async (req, res) => {

try {

  const r = await q(
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
        FILTER (WHERE oi.id IS NOT NULL),
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
    orders: r.rows
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not load orders'
  });

}

}
);

/* =========================
SELLER ORDERS
========================= */

app.get(
'/api/seller/orders',
auth,
role('seller'),
async (req, res) => {

try {

  const r = await q(
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

    ORDER BY o.id DESC, oi.id
    `,
    [req.user.id]
  );

  res.json({
    orders: r.rows
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not load seller orders'
  });

}

}
);

/* =========================
ADMIN ORDERS
========================= */

app.get(
'/api/admin/orders',
auth,
role('admin'),
async (req, res) => {

try {

  const r = await q(
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

    ORDER BY o.id DESC
    `
  );

  res.json({
    orders: r.rows
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not load orders'
  });

}

}
);

/* ADMIN CHANGE ORDER STATUS */

app.put(
'/api/admin/orders/:id/status',
auth,
role('admin'),
async (req, res) => {

try {

  const allowed = [
    'pending',
    'confirmed',
    'shipped',
    'delivered',
    'cancelled'
  ];

  const status =
    String(req.body?.status || '');

  if (!allowed.includes(status)) {

    return res.status(400).json({
      error: 'Invalid order status'
    });

  }

  const r = await q(
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

  if (!r.rowCount) {

    return res.status(404).json({
      error: 'Order not found'
    });

  }

  res.json({
    order: r.rows[0]
  });

} catch (e) {

  console.error(e);

  res.status(500).json({
    error: 'Could not update order'
  });

}

}
);

/* =========================
ADMIN
========================= */

app.get(
'/api/users',
auth,
role('admin'),
async (req, res) => {

const r = await q(
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
  users: r.rows
});

}
);

app.get(
'/api/stats',
auth,
role('admin'),
async (req, res) => {

const [
  a,
  b,
  d
] = await Promise.all([

  q(`
    SELECT COUNT(*)::int n
    FROM users
    WHERE role='customer'
  `),

  q(`
    SELECT COUNT(*)::int n
    FROM users
    WHERE role='seller'
  `),

  q(`
    SELECT COUNT(*)::int n
    FROM products
  `)

]);

res.json({
  customers: a.rows[0].n,
  sellers: b.rows[0].n,
  products: d.rows[0].n
});

}
);

app.get(
'/api/sellers',
async (req, res) => {

const r = await q(
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
  sellers: r.rows
});

}
);

/* =========================
ERROR HANDLER
========================= */

app.use(
(err, req, res, next) => {

console.error(err);

res.status(500).json({
  error: 'Server error'
});

}
);

/* =========================
START
========================= */

init()
.then(() => {

app.listen(
  PORT,
  () => console.log(
    `ShipNova API listening on ${PORT}`
  )
);

})
.catch(e => {

console.error(e);

process.exit(1);

});