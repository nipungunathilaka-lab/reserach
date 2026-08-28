import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/theme.dart';
import '../../widgets/custom_button.dart';
import '../../widgets/custom_textfield.dart';
import '../../services/auth_provider.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({Key? key}) : super(key: key);

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  String? _errorMessage;

  void _login() async {
    final auth = Provider.of<AuthProvider>(context, listen: false);
    
    final result = await auth.login(_emailController.text, _passwordController.text);
    
    if (result['success']) {
      if (mounted) {
        if (result['requires_mfa']) {
          Navigator.of(context).pushReplacementNamed(
            '/verify-mfa',
            arguments: {'challenge_id': result['challenge_id']},
          );
        } else {
          Navigator.of(context).pushReplacementNamed('/main');
        }
      }
    } else {
      setState(() {
        _errorMessage = result['message'];
      });
    }
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final auth = Provider.of<AuthProvider>(context);
    
    return Scaffold(
      body: Center(
        child: Container(
          width: 400,
          padding: const EdgeInsets.all(32),
          decoration: BoxDecoration(
            color: AppTheme.secondaryBackground,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppTheme.accentColor.withOpacity(0.5), width: 1),
            boxShadow: [
              BoxShadow(
                color: AppTheme.accentColor.withOpacity(0.1),
                blurRadius: 30,
                spreadRadius: 2,
              ),
              BoxShadow(
                color: Colors.black.withOpacity(0.5),
                blurRadius: 20,
                offset: const Offset(0, 10),
              )
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Logo
              const Icon(Icons.shield, color: AppTheme.accentColor, size: 64),
              const SizedBox(height: 16),
              const Text(
                'AI-Secure Transfer',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Enter your credentials to access the TEE Enclave',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: AppTheme.textSecondary,
                  fontSize: 14,
                ),
              ),
              const SizedBox(height: 32),
              if (_errorMessage != null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 16.0),
                  child: Text(_errorMessage!, style: const TextStyle(color: AppTheme.errorColor), textAlign: TextAlign.center),
                ),
              CustomTextField(
                controller: _emailController,
                labelText: 'Email Address',
                hintText: 'admin@upce.edu',
                prefixIcon: Icons.email_outlined,
                keyboardType: TextInputType.emailAddress,
              ),
              const SizedBox(height: 16),
              CustomTextField(
                controller: _passwordController,
                labelText: 'Password',
                hintText: '••••••••',
                prefixIcon: Icons.lock_outline,
                obscureText: true,
              ),
              const SizedBox(height: 24),
              CustomButton(
                text: 'LOGIN',
                icon: Icons.login,
                isLoading: auth.isLoading,
                onPressed: _login,
              ),
              const SizedBox(height: 24),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Text('No access?', style: TextStyle(color: AppTheme.textSecondary)),
                  TextButton(
                    onPressed: () {
                      Navigator.of(context).pushNamed('/register');
                    },
                    child: const Text(
                      'Request Key',
                      style: TextStyle(color: AppTheme.accentColor),
                    ),
                  ),
                ],
              )
            ],
          ),
        ),
      ),
    );
  }
}
