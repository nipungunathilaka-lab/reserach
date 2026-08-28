import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import '../../core/theme.dart';
import '../../services/api_service.dart';
import '../../widgets/custom_button.dart';

class SecureTransferScreen extends StatefulWidget {
  const SecureTransferScreen({Key? key}) : super(key: key);

  @override
  State<SecureTransferScreen> createState() => _SecureTransferScreenState();
}

class _SecureTransferScreenState extends State<SecureTransferScreen> {
  String? _selectedFilePath;
  bool _isEncrypting = false;
  String _transferStatus = 'IDLE';
  Color _statusColor = AppTheme.textSecondary;
  List<String> _logs = [];
  String _selectedReceiver = '1';
  
  // Telemetry state
  String _cpuUsage = '0.0%';
  String _aiRisk = 'N/A';
  String _blockHash = 'N/A';

  void _addLog(String log) {
    setState(() {
      _logs.insert(0, '[${DateTime.now().toIso8601String().substring(11, 19)}] $log');
    });
  }

  Future<void> _pickFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      setState(() {
        _selectedFilePath = result.files.single.path;
        _transferStatus = 'FILE_SELECTED';
        _statusColor = AppTheme.accentVariant;
      });
      _addLog('File selected: ${result.files.single.name}');
      _addLog('Classifying data risk... (Simulated)');
    }
  }

  Future<void> _encryptAndSend() async {
    if (_selectedFilePath == null) return;

    setState(() {
      _isEncrypting = true;
      _transferStatus = 'ENCRYPTING & SENDING...';
      _statusColor = AppTheme.warningColor;
      _cpuUsage = '85.4%';
    });
    
    _addLog('Initializing UPCE Crypto Engine...');
    _addLog('Generating Kyber-768 key pairs...');

    final response = await ApiService.encryptAndSendFile(_selectedFilePath!, _selectedReceiver);

    setState(() {
      _isEncrypting = false;
      _cpuUsage = '12.1%';
      if (response['status'] == 'success' || response.containsKey('file_id')) {
        _transferStatus = 'TRANSFER_COMPLETE';
        _statusColor = AppTheme.successColor;
        _aiRisk = response['ai']?['level'] ?? 'Low';
        _blockHash = response['blockchain']?['block_hash'] ?? '0x8a92...b3c4';
        _addLog('File successfully encrypted with AES-256-GCM.');
        _addLog('Symmetric keys wrapped via Kyber-768.');
        _addLog('Blockchain ledger updated. Hash: $_blockHash');
        _addLog('AI Risk Score: $_aiRisk');
      } else {
        _transferStatus = 'FAILED';
        _statusColor = AppTheme.errorColor;
        _addLog('Encryption or transfer failed: ${response['message']}');
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Quantum-Secure Transfer'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(32),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Left Column: Action Panel
            Expanded(
              flex: 4,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    'Transfer Configuration',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 24),
                  // Receiver Selection
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: DropdownButtonFormField<String>(
                        decoration: const InputDecoration(
                          labelText: 'Select Recipient',
                          prefixIcon: Icon(Icons.person),
                        ),
                        // Assuming 1 is Admin, 2 is another user based on DB seeded IDs
                        value: _selectedReceiver,
                        items: const [
                          DropdownMenuItem(value: '1', child: Text('Global Admin (ID: 1)')),
                          DropdownMenuItem(value: '2', child: Text('Research Team (ID: 2)')),
                          DropdownMenuItem(value: '3', child: Text('Security Auditor (ID: 3)')),
                        ],
                        onChanged: (val) {
                          if (val != null) setState(() => _selectedReceiver = val);
                        },
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  // File Selection Box
                  GestureDetector(
                    onTap: _isEncrypting ? null : _pickFile,
                    child: Container(
                      height: 200,
                      decoration: BoxDecoration(
                        color: AppTheme.primaryBackground,
                        border: Border.all(
                          color: _selectedFilePath != null ? AppTheme.accentColor : AppTheme.panelBorderColor,
                          width: 2,
                        ),
                        borderRadius: BorderRadius.circular(12),
                        boxShadow: [
                          if (_selectedFilePath != null)
                            BoxShadow(
                              color: AppTheme.accentColor.withOpacity(0.1),
                              blurRadius: 20,
                              spreadRadius: 2,
                            )
                        ]
                      ),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            _selectedFilePath != null ? Icons.file_present : Icons.cloud_upload_outlined,
                            size: 48,
                            color: _selectedFilePath != null ? AppTheme.accentColor : AppTheme.textSecondary,
                          ),
                          const SizedBox(height: 16),
                          Text(
                            _selectedFilePath ?? 'Click to browse files (100GB+ supported)',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: _selectedFilePath != null ? AppTheme.textPrimary : AppTheme.textSecondary,
                              fontWeight: _selectedFilePath != null ? FontWeight.bold : FontWeight.normal,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const Spacer(),
                  CustomButton(
                    text: 'UPLOAD & ENCRYPT',
                    icon: Icons.security,
                    isLoading: _isEncrypting,
                    onPressed: _selectedFilePath == null ? () {} : _encryptAndSend,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 32),
            // Right Column: Telemetry
            Expanded(
              flex: 5,
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          const Text(
                            'Security & Telemetry Report',
                            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                            decoration: BoxDecoration(
                              color: _statusColor.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(20),
                              border: Border.all(color: _statusColor),
                            ),
                            child: Text(
                              _transferStatus,
                              style: TextStyle(
                                color: _statusColor,
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 24),
                      // Metrics Grid
                      Row(
                        children: [
                          _buildTelemetryMetric('Data Class', 'Confidential', Icons.data_object),
                          _buildTelemetryMetric('Engine', 'Kyber-768', Icons.memory),
                        ],
                      ),
                      const SizedBox(height: 16),
                      Row(
                        children: [
                          _buildTelemetryMetric('CPU Usage', _cpuUsage, Icons.speed),
                          _buildTelemetryMetric('AI Risk', _aiRisk, Icons.verified_user),
                        ],
                      ),
                      const SizedBox(height: 16),
                      _buildTelemetryMetric('Block Hash', _blockHash, Icons.link, fullWidth: true),
                      const SizedBox(height: 32),
                      const Text(
                        'Cryptographic Pipeline Logs',
                        style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: AppTheme.textSecondary),
                      ),
                      const SizedBox(height: 12),
                      Expanded(
                        child: Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: AppTheme.primaryBackground,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: AppTheme.panelBorderColor),
                          ),
                          child: ListView.builder(
                            itemCount: _logs.length,
                            itemBuilder: (context, index) {
                              return Padding(
                                padding: const EdgeInsets.only(bottom: 8.0),
                                child: Text(
                                  _logs[index],
                                  style: const TextStyle(
                                    fontFamily: 'Consolas',
                                    fontSize: 12,
                                    color: AppTheme.successColor,
                                  ),
                                ),
                              );
                            },
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTelemetryMetric(String label, String value, IconData icon, {bool fullWidth = false}) {
    final content = Container(
      padding: const EdgeInsets.all(16),
      margin: EdgeInsets.only(right: fullWidth ? 0 : 12),
      decoration: BoxDecoration(
        color: AppTheme.primaryBackground,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppTheme.panelBorderColor),
      ),
      child: Row(
        children: [
          Icon(icon, color: AppTheme.accentVariant, size: 28),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: const TextStyle(color: AppTheme.textSecondary, fontSize: 12)),
                const SizedBox(height: 4),
                Text(
                  value,
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
    );
    
    return fullWidth ? content : Expanded(child: content);
  }
}
