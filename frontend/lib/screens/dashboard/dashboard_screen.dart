import 'package:flutter/material.dart';
import '../../core/theme.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('System Dashboard'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {},
            tooltip: 'Refresh Data',
          ),
          const SizedBox(width: 16),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enclave Overview',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: _buildMetricCard(
                    title: 'TEE Status',
                    value: 'SECURE',
                    icon: Icons.shield,
                    color: AppTheme.successColor,
                  ),
                ),
                const SizedBox(width: 24),
                Expanded(
                  child: _buildMetricCard(
                    title: 'Active Transfers',
                    value: '3',
                    icon: Icons.swap_horiz,
                    color: AppTheme.accentColor,
                  ),
                ),
                const SizedBox(width: 24),
                Expanded(
                  child: _buildMetricCard(
                    title: 'AI Threat Level',
                    value: 'LOW',
                    icon: Icons.analytics,
                    color: AppTheme.successColor,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 48),
            const Text(
              'Recent System Activity',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            Card(
              child: ListView.separated(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: 5,
                separatorBuilder: (context, index) => const Divider(),
                itemBuilder: (context, index) {
                  return ListTile(
                    leading: Icon(
                      index % 2 == 0 ? Icons.check_circle : Icons.info,
                      color: index % 2 == 0 ? AppTheme.successColor : AppTheme.accentColor,
                    ),
                    title: Text(
                      index % 2 == 0 
                          ? 'Kyber-768 Key Exchange Successful'
                          : 'Anomaly Detection scan completed (0 issues)',
                    ),
                    subtitle: Text('2026-08-27 14:${50 - index}:00'),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricCard({
    required String title,
    required String value,
    required IconData icon,
    required Color color,
  }) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: AppTheme.textSecondary,
                    fontSize: 16,
                  ),
                ),
                Icon(icon, color: color, size: 28),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              value,
              style: TextStyle(
                color: color,
                fontSize: 32,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
