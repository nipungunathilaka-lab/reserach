import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../core/theme.dart';
import '../../widgets/custom_button.dart';
import '../../widgets/custom_textfield.dart';
import '../../services/auth_provider.dart';

class RegisterScreen extends StatefulWidget {
  const RegisterScreen({Key? key}) : super(key: key);

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final _nameController = TextEditingController();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _companyController = TextEditingController();
  final _jobRoleController = TextEditingController();
  String? _errorMessage;

  void _register() async {
    final auth = Provider.of<AuthProvider>(context, listen: false);
    
    final result = await auth.register({
      'full_name': _nameController.text,
      'email': _emailController.text,
      'password': _passwordController.text,
      'company_name': _companyController.text.isNotEmpty ? _companyController.text : null,
      'job_role': _jobRoleController.text.isNotEmpty ? _jobRoleController.text : null,
    });

    if (result['success']) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Registration successful. Please login.')));
        Navigator.of(context).pushReplacementNamed('/login');
      }
    } else {
      setState(() {
        _errorMessage = result['message'];
      });
    }
  }

  @override
  void dispose() {
    _nameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _companyController.dispose();
    _jobRoleController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final auth = Provider.of<AuthProvider>(context);
    
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          child: Container(
            width: 450,
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
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.person_add_alt_1, color: AppTheme.accentColor, size: 64),
                const SizedBox(height: 16),
                const Text(
                  'Create Access Key',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                const SizedBox(height: 32),
                if (_errorMessage != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16.0),
                    child: Text(_errorMessage!, style: const TextStyle(color: AppTheme.errorColor), textAlign: TextAlign.center),
                  ),
                CustomTextField(
                  controller: _nameController,
                  labelText: 'Full Name',
                  hintText: 'John Doe',
                  prefixIcon: Icons.person_outline,
                ),
                const SizedBox(height: 16),
                CustomTextField(
                  controller: _emailController,
                  labelText: 'Email Address',
                  hintText: 'user@upce.edu',
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
                const SizedBox(height: 16),
                CustomTextField(
                  controller: _companyController,
                  labelText: 'Company (Optional)',
                  hintText: 'Acme Corp',
                  prefixIcon: Icons.business_outlined,
                ),
                const SizedBox(height: 16),
                CustomTextField(
                  controller: _jobRoleController,
                  labelText: 'Job Role (Optional)',
                  hintText: 'Security Analyst',
                  prefixIcon: Icons.work_outline,
                ),
                const SizedBox(height: 24),
                CustomButton(
                  text: 'REGISTER',
                  icon: Icons.check_circle_outline,
                  isLoading: auth.isLoading,
                  onPressed: _register,
                ),
                const SizedBox(height: 24),
                TextButton(
                  onPressed: () => Navigator.of(context).pushReplacementNamed('/login'),
                  child: const Text('Already have an account? Login', style: TextStyle(color: AppTheme.accentColor)),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
