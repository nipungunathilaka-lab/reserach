class AppConstants {
  static const String appName = 'AI-Secure File Transfer';
  static const String apiBaseUrl = 'http://127.0.0.1:8000/api';
  
  // Endpoints
  static const String loginEndpoint = '/auth/login';
  static const String registerEndpoint = '/auth/register';
  static const String verifyMfaEndpoint = '/auth/verify-mfa';
  static const String sendEndpoint = '/files/send';
  static const String blockchainEndpoint = '/blockchain/logs';
  static const String aiAlertsEndpoint = '/logs/ai-alerts';
}
