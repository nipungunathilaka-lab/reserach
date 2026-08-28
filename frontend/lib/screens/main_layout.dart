import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../widgets/sidebar.dart';
import 'dashboard/dashboard_screen.dart';
import 'vault/file_vault_screen.dart';
import 'transfer/secure_transfer_screen.dart';
import 'transfer/received_files_screen.dart';
import 'audit/transfer_logs_screen.dart';
import 'audit/blockchain_logs_screen.dart';
import 'audit/ai_alerts_screen.dart';
import '../services/auth_provider.dart';

class MainLayout extends StatefulWidget {
  const MainLayout({Key? key}) : super(key: key);

  @override
  State<MainLayout> createState() => _MainLayoutState();
}

class _MainLayoutState extends State<MainLayout> {
  int _selectedIndex = 0;

  final List<Widget> _screens = const [
    DashboardScreen(),
    FileVaultScreen(),
    SecureTransferScreen(),
    ReceivedFilesScreen(),
    TransferLogsScreen(),
    BlockchainLogsScreen(),
    AiAlertsScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    final auth = Provider.of<AuthProvider>(context);
    
    // Auth Guard
    if (!auth.isAuthenticated) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        Navigator.of(context).pushReplacementNamed('/login');
      });
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    return Scaffold(
      body: Row(
        children: [
          Sidebar(
            selectedIndex: _selectedIndex,
            onItemSelected: (index) {
              setState(() {
                _selectedIndex = index;
              });
            },
          ),
          Expanded(
            child: _screens[_selectedIndex],
          ),
        ],
      ),
    );
  }
}
