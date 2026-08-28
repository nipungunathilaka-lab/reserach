import 'package:flutter/material.dart';
import '../core/theme.dart';

class Sidebar extends StatelessWidget {
  final int selectedIndex;
  final Function(int) onItemSelected;

  const Sidebar({
    Key? key,
    required this.selectedIndex,
    required this.onItemSelected,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 250,
      color: AppTheme.secondaryBackground,
      child: Column(
        children: [
          const SizedBox(height: 32),
          // Logo / Header
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.shield, color: AppTheme.accentColor, size: 32),
              const SizedBox(width: 12),
              const Text(
                'AI-Secure',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            'TEE Enclave Connected',
            style: TextStyle(
              color: AppTheme.successColor,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 32),
          
          Expanded(
            child: ListView(
              children: [
                _buildNavItem(icon: Icons.dashboard_outlined, title: 'Dashboard', index: 0),
                _buildNavItem(icon: Icons.lock_outline, title: 'File Vault', index: 1),
                _buildNavItem(icon: Icons.send_outlined, title: 'Send File', index: 2),
                _buildNavItem(icon: Icons.download_outlined, title: 'Received Files', index: 3),
                const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                  child: Text('AUDIT & SECURITY', style: TextStyle(color: AppTheme.textSecondary, fontSize: 10, fontWeight: FontWeight.bold)),
                ),
                _buildNavItem(icon: Icons.history_outlined, title: 'Transfer Logs', index: 4),
                _buildNavItem(icon: Icons.link_outlined, title: 'Blockchain Logs', index: 5),
                _buildNavItem(icon: Icons.warning_amber_outlined, title: 'AI Alerts', index: 6),
              ],
            ),
          ),
          
          // Logout Button
          Material(
            color: Colors.transparent,
            child: ListTile(
              leading: const Icon(Icons.logout, color: AppTheme.errorColor),
              title: const Text('Logout', style: TextStyle(color: AppTheme.errorColor)),
              onTap: () {
                Navigator.of(context).pushReplacementNamed('/login');
              },
            ),
          ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  Widget _buildNavItem({
    required IconData icon,
    required String title,
    required int index,
  }) {
    final isSelected = selectedIndex == index;
    
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: isSelected ? AppTheme.accentColor.withOpacity(0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: isSelected ? AppTheme.accentColor.withOpacity(0.3) : Colors.transparent,
          width: 1,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: ListTile(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          leading: Icon(
            icon,
            color: isSelected ? AppTheme.accentColor : AppTheme.textSecondary,
          ),
          title: Text(
            title,
            style: TextStyle(
              color: isSelected ? AppTheme.accentColor : AppTheme.textPrimary,
              fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
            ),
          ),
          onTap: () => onItemSelected(index),
        ),
      ),
    );
  }
}
