import { AnalyticsService } from '../services/analyticsService';

describe('AnalyticsService', () => {
  it('generates a consistent analytics report', () => {
    const report = AnalyticsService.generateReport('demo-user');
    expect(report.userId).toBe('demo-user');
    expect(report.totalSpendMonthly).toBeGreaterThan(0);
    expect(report.monthlyTrend).toHaveLength(6);
    expect(report.yearlyTrend).toHaveLength(5);
    expect(report.utilityUsageBreakdown).toHaveProperty('water');
    expect(report.predictiveInsight).toContain('Spending is expected');
  });

  it('provides payment dashboard analytics', async () => {
    const service = new AnalyticsService();
    const dashboard = await service.getPaymentDashboardAnalytics();

    expect(dashboard.totalPayments).toBeGreaterThanOrEqual(0);
    expect(dashboard.totalVolume).toBeGreaterThanOrEqual(0);
    expect(dashboard.averagePayment).toBeGreaterThanOrEqual(0);
    expect(dashboard.monthlyTrend.length).toBeGreaterThanOrEqual(0);
    expect(dashboard.statusDistribution).toBeDefined();
    expect(Array.isArray(dashboard.insights)).toBe(true);
  });
});
