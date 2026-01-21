import { Controller, Get, Post, Put, Delete, UseGuards } from '@nestjs/common';

// Mock decorators for demonstration
const Public = () => (target: any, key?: string, descriptor?: any) => descriptor;
const Roles = (...roles: string[]) => (target: any, key?: string, descriptor?: any) => descriptor;
const AuthGuard = (type: string) => class {};
const RolesGuard = class {};

// ============================================
// PUBLIC CONTROLLER
// ============================================

@Controller('public')
export class PublicController {
  // AP001: Public without explicit intent
  @Get('products')
  getProducts() {
    return { products: [] };
  }

  // Explicitly public (OK)
  @Public()
  @Get('health')
  healthCheck() {
    return { status: 'ok' };
  }

  // AP007: Sensitive route keywords
  @Get('admin/config')
  getAdminConfig() {
    return { config: {} };
  }
}

// ============================================
// PROTECTED CONTROLLER
// ============================================

@Controller('protected')
@UseGuards(AuthGuard('jwt'))
export class ProtectedController {
  // Inherits class-level guard (OK)
  @Get('profile')
  getProfile() {
    return { user: {} };
  }

  // AP003: Controller/action conflict - @Public overrides class @UseGuards
  @Public()
  @Get('semi-public')
  getSemiPublic() {
    return { data: {} };
  }

  // Properly protected write (OK)
  @Post('orders')
  createOrder() {
    return { orderId: 123 };
  }

  // AP002: AllowAnonymous on write
  @Public()
  @Post('feedback')
  submitFeedback() {
    return { success: true };
  }
}

// ============================================
// ROLE-BASED CONTROLLER
// ============================================

@Controller('admin')
@UseGuards(AuthGuard('jwt'), RolesGuard)
export class AdminController {
  // AP006: Weak role naming
  @Roles('admin')
  @Get('dashboard')
  getDashboard() {
    return { dashboard: {} };
  }

  // AP005: Excessive role access
  @Roles('admin', 'manager', 'analyst', 'viewer', 'reporter')
  @Get('reports')
  getReports() {
    return { reports: [] };
  }

  // Better role naming (OK)
  @Roles('billing-admin')
  @Get('billing')
  getBilling() {
    return { billing: {} };
  }

  // AP004 would not trigger here because class has guards
  @Delete('users/:id')
  deleteUser() {
    return { deleted: true };
  }
}

// ============================================
// UNPROTECTED CONTROLLER (BAD!)
// ============================================

@Controller('api')
export class UnprotectedApiController {
  // AP001: Public without explicit intent
  @Get('data')
  getData() {
    return { data: [] };
  }

  // AP004: Missing auth on writes (CRITICAL)
  @Post('data')
  createData() {
    return { id: 1 };
  }

  // AP004: Missing auth on writes (CRITICAL)
  @Put('data/:id')
  updateData() {
    return { updated: true };
  }

  // AP004: Missing auth on writes (CRITICAL)
  @Delete('data/:id')
  deleteData() {
    return { deleted: true };
  }
}
