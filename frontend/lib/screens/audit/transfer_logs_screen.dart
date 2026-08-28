import 'package:flutter/material.dart';
import '../../core/theme.dart';

class TransferLogsScreen extends StatelessWidget {
  const TransferLogsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Transfer Logs'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Activity History',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 24),
            Expanded(
              child: Card(
                child: DataTable(
                  columns: const [
                    DataColumn(label: Text('Time')),
                    DataColumn(label: Text('Action')),
                    DataColumn(label: Text('Details')),
                    DataColumn(label: Text('Status')),
                  ],
                  rows: [
                    DataRow(cells: [
                      DataCell(Text(DateTime.now().subtract(const Duration(minutes: 5)).toString().substring(11, 16))),
                      const DataCell(Text('File Encrypted')),
                      const DataCell(Text('confidential_report.pdf (Kyber-768 + AES)')),
                      DataCell(Text('SUCCESS', style: TextStyle(color: AppTheme.successColor, fontWeight: FontWeight.bold))),
                    ]),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
