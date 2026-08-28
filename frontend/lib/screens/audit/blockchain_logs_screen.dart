import 'package:flutter/material.dart';
import '../../core/theme.dart';
import '../../services/api_service.dart';

class BlockchainLogsScreen extends StatefulWidget {
  const BlockchainLogsScreen({Key? key}) : super(key: key);

  @override
  State<BlockchainLogsScreen> createState() => _BlockchainLogsScreenState();
}

class _BlockchainLogsScreenState extends State<BlockchainLogsScreen> {
  List<dynamic> _logs = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _fetchLogs();
  }

  Future<void> _fetchLogs() async {
    setState(() => _isLoading = true);
    final logs = await ApiService.getBlockchainLogs();
    setState(() {
      _logs = logs;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Immutable Blockchain Logs'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchLogs),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Hyperledger Fabric Ledger Sync',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 24),
            Expanded(
              child: Card(
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : _logs.isEmpty
                        ? const Center(child: Text('No blockchain logs found.'))
                        : ListView.builder(
                            itemCount: _logs.length,
                            itemBuilder: (context, index) {
                              final log = _logs[index];
                              return ListTile(
                                leading: const Icon(Icons.link, color: AppTheme.accentVariant),
                                title: Text('Block #${log['block_number'] ?? 'N/A'} - Action: ${log['action'] ?? 'N/A'}'),
                                subtitle: Text('Hash: ${log['hash'] ?? 'N/A'}\nTimestamp: ${log['timestamp'] ?? 'N/A'}'),
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
