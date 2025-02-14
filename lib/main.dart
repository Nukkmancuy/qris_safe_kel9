import 'package:flutter/material.dart';
import 'package:qr_code_scanner/qr_code_scanner.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:url_launcher/url_launcher.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(primarySwatch: Colors.blueGrey),
      home: const QRViewExample(),
    );
  }
}

class QRViewExample extends StatefulWidget {
  const QRViewExample({super.key});

  @override
  State<StatefulWidget> createState() => _QRViewExampleState();
}

class _QRViewExampleState extends State<QRViewExample> {
  final GlobalKey qrKey = GlobalKey(debugLabel: 'QR');
  Barcode? result;
  QRViewController? controller;
  @override
  void reassemble() {
    super.reassemble();
    controller!.pauseCamera();
    controller!.resumeCamera();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('QR Safe Scanner')),
      body: Column(
        children: <Widget>[
          Expanded(flex: 4, child: _buildQrView(context)),
          Expanded(
            flex: 1,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: <Widget>[
                if (result != null)
                  Text('Result: ${result!.code}')
                else
                  const Text('Scan a code'),
                ElevatedButton(
                  onPressed: result != null && result!.code != null
                      ? () => _checkWithVirusTotal(result!.code!)
                      : null,
                  child: const Text('Check with VirusTotal'),
                ),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _buildQrView(BuildContext context) {
    return QRView(
      key: qrKey,
      onQRViewCreated: _onQRViewCreated,
      overlay: QrScannerOverlayShape(
        borderColor: Colors.white,
        borderRadius: 10,
        borderLength: 30,
        borderWidth: 10,
        cutOutSize: MediaQuery.of(context).size.width * 0.8,
      ),
    );
  }

  void _onQRViewCreated(QRViewController controller) {
    setState(() {
      this.controller = controller;
    });
    controller.scannedDataStream.listen((scanData) {
      setState(() {
        result = scanData;
      });
    });
  }

  Future<void> _checkWithVirusTotal(String url) async {
    const apiKey = '23ce08f804220ff9f46b912df839baa8cd7a79f5cd57e0f18b8e858f86cac65d';
    final encodedUrl = base64Url.encode(utf8.encode(url)).replaceAll('=', ''); // Encode and remove padding
    final apiUrl = 'https://www.virustotal.com/api/v3/urls/$encodedUrl';

    try {
      final response = await http.get(
        Uri.parse(apiUrl),
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/json',
        },
      );

      if (response.statusCode == 200) {
        final jsonResponse = json.decode(response.body);

        final scanResult = jsonResponse['data']['attributes']['last_analysis_stats'];

        // Periksa apakah malicious atau suspicious lebih dari 0
        if (scanResult is Map) {
          int maliciousCount = scanResult['malicious'] ?? 0;
          int suspiciousCount = scanResult['suspicious'] ?? 0;

          if (maliciousCount > 0 || suspiciousCount > 0) {
            // Tampilkan dialog peringatan
            _showDangerDialog(maliciousCount, suspiciousCount);
          } else {
            // Tampilkan hasil pemindaian (aman)
            _showScanResultDialog(scanResult as Map<String, dynamic>, url, maliciousCount, suspiciousCount);
          }
        }
      } else {
        _showErrorDialog('Error: Unable to scan the URL with VirusTotal.');
      }
    } catch (e) {
      _showErrorDialog('Error: $e');
    }
  }

  // Fungsi untuk menampilkan dialog peringatan
  void _showDangerDialog(int maliciousCount, int suspiciousCount) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Peringatan!'),
        content: Text('Tautan ini terdeteksi berbahaya atau mencurigakan.\n'
            'Jumlah Berbahaya: $maliciousCount\n'
            'Jumlah Mencurigakan: $suspiciousCount'),
        actions: <Widget>[
          TextButton(
            child: const Text('OK'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  // Fungsi untuk menampilkan hasil pemindaian (aman) dengan tombol buka link
  void _showScanResultDialog(Map<String, dynamic> scanResult, String url,int maliciousCount, int suspiciousCount) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Hasil Pemindaian'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Hasil analisis VirusTotal:'),
            Text('Tautan ini terdeteksi berbahaya atau mencurigakan.\n'
                'Jumlah Berbahaya: $maliciousCount\n'
                'Jumlah Mencurigakan: $suspiciousCount'),
            // for (var entry in scanResult.entries)
            //   Text('${entry.key}: ${entry.value}'),
          ],
        ),
        actions: <Widget>[
          TextButton(
            child: const Text('Buka Tautan'),
            onPressed: () async {
              if (await canLaunchUrl(Uri.parse(url))) {
                await launchUrl(Uri.parse(url));
              } else {
                _showErrorDialog('Tidak dapat membuka tautan.');
              }
              Navigator.of(context).pop();
            },
          ),
          TextButton(
            child: const Text('Tutup'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  void _showErrorDialog(String message) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Error'),
        content: Text(message),
        actions: <Widget>[
          TextButton(
            child: const Text('OK'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    controller?.dispose();
    super.dispose();
  }
}