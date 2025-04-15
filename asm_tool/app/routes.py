from flask import render_template, request, jsonify, send_file
from app import app, socketio
from app.modules.scanner import ASMScanner
import os
import json
from datetime import datetime

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Please upload a CSV file'}), 400
    
    # Save the file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'input.csv')
    file.save(filepath)
    
    # Initialize scanner
    scanner = ASMScanner(filepath)
    
    # Start scanning in background
    socketio.start_background_task(scanner.scan_domains)
    
    return jsonify({'message': 'Scan started successfully'})

@app.route('/status')
def get_status():
    status_file = os.path.join(app.config['UPLOAD_FOLDER'], 'scan_status.json')
    if os.path.exists(status_file):
        with open(status_file, 'r') as f:
            return jsonify(json.load(f))
    return jsonify({'status': 'No scan in progress'})

@app.route('/results')
def get_results():
    results_file = os.path.join(app.config['UPLOAD_FOLDER'], 'scan_results.json')
    if os.path.exists(results_file):
        return send_file(results_file, mimetype='application/json')
    return jsonify({'error': 'No results available'}), 404

if __name__ == '__main__':
    socketio.run(app, debug=True) 