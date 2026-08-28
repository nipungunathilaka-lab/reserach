import 'package:flutter/material.dart';
import '../../core/theme.dart';

class ReceivedFilesScreen extends StatelessWidget {
  const ReceivedFilesScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Received Files'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Incoming Transfers',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 24),
            Expanded(
              child: Card(
                child: DataTable(
                  columns: const [
                    DataColumn(label: Text('File Name')),
                    DataColumn(label: Text('Sender')),
                    DataColumn(label: Text('Date Received')),
                    DataColumn(label: Text('Status')),
                    DataColumn(label: Text('Action')),
                  ],
                  rows: [
                    DataRow(cells: [
                      DataCell(Row(children: [Icon(Icons.description, color: AppTheme.accentVariant, size: 16), const SizedBox(width: 8), const Text('project_alpha_keys.enc')])),
                      const DataCell(Text('admin@upce.edu')),
                      DataCell(Text(DateTime.now().subtract(const Duration(hours: 1)).toString().substring(0, 16))),
                      DataCell(Text('Pending Decryption', style: TextStyle(color: AppTheme.warningColor))),
                      DataCell(
                        ElevatedButton.icon(
                          icon: const Icon(Icons.lock_open, size: 16),
                          label: const Text('Decrypt & Download'),
                          onPressed: () {},
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppTheme.accentColor,
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                            textStyle: const TextStyle(fontSize: 12),
                          ),
                        ),
                      ),
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
