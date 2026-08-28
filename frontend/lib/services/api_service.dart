import 'dart:io';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../core/constants.dart';

class ApiService {
  static Future<Map<String, String>> _getHeaders() async {
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString('jwt_token');
    return {
      'Content-Type': 'application/json',
      if (token != null) 'Authorization': 'Bearer $token',
    };
  }

  /// Check if the backend TEE enclave is running
  static Future<bool> checkHealth() async {
    try {
      final response = await http.get(Uri.parse('http://127.0.0.1:8000/'));
      if (response.statusCode == 200) {
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Send file encryption and transfer request to backend using chunking for large files
  static Future<Map<String, dynamic>> encryptAndSendFile(String filePath, String receiverId) async {
    try {
      final headers = await _getHeaders();
      // Remove Content-Type so MultipartRequest can set its own boundary correctly
      headers.remove('Content-Type');

      final file = File(filePath);
      final length = await file.length();
      final fileName = filePath.split(Platform.pathSeparator).last;
      
      const chunkSize = 5 * 1024 * 1024; // 5 MB chunks
      final totalChunks = (length / chunkSize).ceil();
      // Generate a unique upload ID based on timestamp
      final uploadId = DateTime.now().millisecondsSinceEpoch.toString();

      for (int i = 0; i < totalChunks; i++) {
        var request = http.MultipartRequest(
          'POST',
          Uri.parse('${AppConstants.apiBaseUrl}/files/upload-chunk'),
        );
        request.headers.addAll(headers);

        int start = i * chunkSize;
        int end = (start + chunkSize < length) ? start + chunkSize : length;
        var stream = file.openRead(start, end);
        var lengthToRead = end - start;

        request.fields['receiver_id'] = receiverId;
        request.fields['upload_id'] = uploadId;
        request.fields['chunk_index'] = i.toString();
        request.fields['total_chunks'] = totalChunks.toString();
        request.fields['file_name'] = fileName;

        var multipartFile = http.MultipartFile('file', stream, lengthToRead, filename: fileName);
        request.files.add(multipartFile);

        var streamedResponse = await request.send();
        if (streamedResponse.statusCode != 200) {
          var err = await streamedResponse.stream.bytesToString();
          return {'status': 'error', 'message': 'Failed at chunk $i: ${streamedResponse.statusCode} - $err'};
        }
      }

      // All chunks uploaded, begin polling for completion
      while (true) {
        await Future.delayed(const Duration(seconds: 2));
        final statusResponse = await http.get(
          Uri.parse('${AppConstants.apiBaseUrl}/files/status/$uploadId'),
          headers: await _getHeaders(), // Need standard headers here
        );
        if (statusResponse.statusCode == 200) {
          final data = jsonDecode(statusResponse.body);
          if (data['status'] == 'completed') {
            return data['result'];
          } else if (data['status'] == 'error') {
            return {'status': 'error', 'message': data['message']};
          }
          // If status is 'processing', continue polling
        } else {
          return {'status': 'error', 'message': 'Failed to poll status: ${statusResponse.statusCode}'};
        }
      }
    } catch (e) {
      return {
        'status': 'error',
        'message': 'Network error: $e',
      };
    }
  }

  /// Fetch blockchain logs
  static Future<List<dynamic>> getBlockchainLogs() async {
    try {
      final headers = await _getHeaders();
      final response = await http.get(
        Uri.parse('${AppConstants.apiBaseUrl}${AppConstants.blockchainEndpoint}'),
        headers: headers,
      );
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      return [];
    } catch (e) {
      return [];
    }
  }

  /// Fetch AI Alerts
  static Future<List<dynamic>> getAiAlerts() async {
    try {
      final headers = await _getHeaders();
      final response = await http.get(
        Uri.parse('${AppConstants.apiBaseUrl}${AppConstants.aiAlertsEndpoint}'),
        headers: headers,
      );
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      return [];
    } catch (e) {
      return [];
    }
  }
}
