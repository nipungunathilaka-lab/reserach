import 'package:flutter/material.dart';
import '../../core/theme.dart';
import '../../services/api_service.dart';

class AiAlertsScreen extends StatefulWidget {
  const AiAlertsScreen({Key? key}) : super(key: key);

  @override
  State<AiAlertsScreen> createState() => _AiAlertsScreenState();
}

class _AiAlertsScreenState extends State<AiAlertsScreen> {
  List<dynamic> _alerts = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _fetchAlerts();
  }

  Future<void> _fetchAlerts() async {
    setState(() => _isLoading = true);
    final alerts = await ApiService.getAiAlerts();
    setState(() {
      _alerts = alerts;
      _isLoading = false;
    });
  }

  Color _getRiskColor(String riskLevel) {
    switch (riskLevel.toLowerCase()) {
      case 'high':
        return AppTheme.errorColor;
      case 'medium':
        return AppTheme.warningColor;
      case 'low':
        return AppTheme.successColor;
      default:
        return AppTheme.textSecondary;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('AI Threat Intelligence Alerts'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAlerts),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Real-time Malware & Anomaly Detection',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 24),
            Expanded(
              child: Card(
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : _alerts.isEmpty
                        ? const Center(child: Text('No AI alerts found.'))
                        : ListView.builder(
                            itemCount: _alerts.length,
                            itemBuilder: (context, index) {
                              final alert = _alerts[index];
                              final riskLevel = alert['risk_level'] ?? 'Unknown';
                              return ListTile(
                                leading: Icon(
                                  Icons.warning_amber_rounded,
                                  color: _getRiskColor(riskLevel),
                                  size: 32,
                                ),
                                title: Text('Alert ID: ${alert['id'] ?? 'N/A'} - Risk: $riskLevel'),
                                subtitle: Text('Details: ${alert['details'] ?? 'No details provided'}\nTimestamp: ${alert['timestamp'] ?? 'N/A'}'),
                                isThreeLine: true,
                              );
                            },
                          ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
