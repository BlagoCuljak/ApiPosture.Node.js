import express from 'express';
import passport from 'passport';

const app = express();
const router = express.Router();

// Middleware examples
const requireAuth = (req: any, res: any, next: any) => next();
const allowAnonymous = (req: any, res: any, next: any) => next();
const requireRole = (role: string) => (req: any, res: any, next: any) => next();

// ============================================
// PUBLIC ENDPOINTS (various patterns)
// ============================================

// AP001: Public without explicit intent (no auth, no @Public)
app.get('/api/products', (req, res) => {
  res.json({ products: [] });
});

// AP007: Sensitive route keywords - admin in public route
app.get('/api/admin/stats', (req, res) => {
  res.json({ stats: {} });
});

// Explicitly public (OK - intentional)
app.get('/api/health', allowAnonymous, (req, res) => {
  res.json({ status: 'ok' });
});

// ============================================
// WRITE OPERATIONS
// ============================================

// AP002: AllowAnonymous on write operation
app.post('/api/feedback', allowAnonymous, (req, res) => {
  res.json({ success: true });
});

// AP004: Missing auth on writes (CRITICAL)
app.post('/api/orders', (req, res) => {
  res.json({ orderId: 123 });
});

// AP004: Missing auth on writes (CRITICAL)
app.delete('/api/users/:id', (req, res) => {
  res.json({ deleted: true });
});

// Protected write (OK)
app.post('/api/protected/orders', requireAuth, (req, res) => {
  res.json({ orderId: 123 });
});

// ============================================
// AUTHENTICATED ENDPOINTS
// ============================================

// Properly protected with passport
app.get('/api/profile', passport.authenticate('jwt'), (req, res) => {
  res.json({ user: {} });
});

// Protected with custom middleware
app.get('/api/settings', requireAuth, (req, res) => {
  res.json({ settings: {} });
});

// ============================================
// ROLE-BASED ENDPOINTS
// ============================================

// AP005: Excessive role access (>3 roles)
app.get(
  '/api/reports',
  requireAuth,
  requireRole('admin'),
  requireRole('manager'),
  requireRole('analyst'),
  requireRole('viewer'),
  (req, res) => {
    res.json({ reports: [] });
  }
);

// AP006: Weak role naming
app.get('/api/dashboard', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ dashboard: {} });
});

// Better role naming (OK)
app.get('/api/billing', requireAuth, requireRole('billing-admin'), (req, res) => {
  res.json({ billing: {} });
});

// ============================================
// ROUTER-BASED ENDPOINTS
// ============================================

// Router with prefix
router.get('/items', requireAuth, (req, res) => {
  res.json({ items: [] });
});

router.post('/items', requireAuth, (req, res) => {
  res.json({ itemId: 1 });
});

// AP001: Public router endpoint
router.get('/public-items', (req, res) => {
  res.json({ items: [] });
});

app.use('/api/v2', router);

export default app;
