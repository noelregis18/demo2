document.addEventListener('DOMContentLoaded', function() {
    // Theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    const icon = themeToggle.querySelector('i');
    
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        body.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);
    }
    
    themeToggle.addEventListener('click', () => {
        const currentTheme = body.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });
    
    function updateThemeIcon(theme) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
    
    // File upload handling
    const uploadForm = document.getElementById('upload-form');
    const fileInput = document.getElementById('csv-file');
    
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const file = fileInput.files[0];
        if (!file) {
            showAlert('Please select a CSV file', 'danger');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            if (response.ok) {
                showAlert('Scan started successfully', 'success');
                startProgressMonitoring();
            } else {
                showAlert(data.error || 'Upload failed', 'danger');
            }
        } catch (error) {
            showAlert('Error uploading file', 'danger');
        }
    });
    
    // WebSocket connection for real-time updates
    const socket = io();
    
    socket.on('status_update', (data) => {
        updateProgress(data);
    });
    
    function updateProgress(data) {
        const progressContainer = document.getElementById('scan-progress');
        const noScan = document.getElementById('no-scan');
        const progressBar = progressContainer.querySelector('.progress-bar');
        const currentDomain = document.getElementById('current-domain');
        const scanStatus = document.getElementById('scan-status');
        
        if (data.status === 'initialized') {
            progressContainer.classList.add('d-none');
            noScan.classList.remove('d-none');
            return;
        }
        
        progressContainer.classList.remove('d-none');
        noScan.classList.add('d-none');
        
        const progress = (data.completed / data.total) * 100;
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
        
        currentDomain.textContent = `Scanning: ${data.current_domain}`;
        scanStatus.textContent = `Progress: ${data.completed}/${data.total} domains`;
        
        if (data.status === 'completed') {
            loadResults();
        }
    }
    
    async function loadResults() {
        try {
            const response = await fetch('/results');
            if (response.ok) {
                const results = await response.json();
                displayResults(results);
            }
        } catch (error) {
            showAlert('Error loading results', 'danger');
        }
    }
    
    function displayResults(results) {
        const resultsContainer = document.getElementById('results-container');
        const noResults = document.getElementById('no-results');
        const resultsTable = document.getElementById('results-table');
        
        if (Object.keys(results).length === 0) {
            resultsContainer.classList.add('d-none');
            noResults.classList.remove('d-none');
            return;
        }
        
        resultsContainer.classList.remove('d-none');
        noResults.classList.add('d-none');
        
        resultsTable.innerHTML = '';
        
        for (const [domain, data] of Object.entries(results)) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${domain}</td>
                <td class="risk-${getRiskClass(data.risk_score)}">${data.risk_score}</td>
                <td>${data.subdomains.length}</td>
                <td>${data.open_ports.length}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="showDetailedResults('${domain}')">
                        Details
                    </button>
                </td>
            `;
            resultsTable.appendChild(row);
        }
    }
    
    function getRiskClass(score) {
        if (score >= 70) return 'high';
        if (score >= 40) return 'medium';
        return 'low';
    }
    
    function showDetailedResults(domain) {
        const modal = new bootstrap.Modal(document.getElementById('resultsModal'));
        const detailedResults = document.getElementById('detailed-results');
        
        // Fetch detailed results for the domain
        fetch(`/results/${domain}`)
            .then(response => response.json())
            .then(data => {
                detailedResults.innerHTML = formatDetailedResults(data);
                modal.show();
            })
            .catch(error => {
                showAlert('Error loading detailed results', 'danger');
            });
    }
    
    function formatDetailedResults(data) {
        return `
            <div class="mb-4">
                <h4>Domain Information</h4>
                <p><strong>Domain:</strong> ${data.domain}</p>
                <p><strong>Scan Date:</strong> ${new Date(data.scan_date).toLocaleString()}</p>
                <p><strong>Risk Score:</strong> <span class="risk-${getRiskClass(data.risk_score)}">${data.risk_score}</span></p>
                <p><strong>Risk Summary:</strong> ${data.risk_summary}</p>
            </div>
            
            <div class="mb-4">
                <h4>Subdomains (${data.subdomains.length})</h4>
                <ul class="list-group">
                    ${data.subdomains.map(sub => `<li class="list-group-item">${sub}</li>`).join('')}
                </ul>
            </div>
            
            <div class="mb-4">
                <h4>Open Ports (${data.open_ports.length})</h4>
                <ul class="list-group">
                    ${data.open_ports.map(port => `<li class="list-group-item">${port}</li>`).join('')}
                </ul>
            </div>
            
            <div class="mb-4">
                <h4>Technology Stack</h4>
                <ul class="list-group">
                    ${data.tech_stack.map(tech => `<li class="list-group-item">${tech}</li>`).join('')}
                </ul>
            </div>
            
            <div class="mb-4">
                <h4>Security Headers</h4>
                <ul class="list-group">
                    ${Object.entries(data.headers).map(([header, value]) => 
                        `<li class="list-group-item"><strong>${header}:</strong> ${value}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const container = document.querySelector('.container');
        container.insertBefore(alertDiv, container.firstChild);
        
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}); 