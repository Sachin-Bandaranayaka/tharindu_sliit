/**
 * CVSS Score Prediction & Risk Assessment Tool
 * Dashboard JavaScript for visualizing risk assessment data
 */

// DOM Elements
const elements = {
    totalVulnerabilities: document.querySelector('#total-vulnerabilities .summary-value'),
    averageScore: document.querySelector('#average-score .summary-value'),
    highestRisk: document.querySelector('#highest-risk .summary-value'),
    riskIndex: document.querySelector('#risk-index .summary-value'),
    vulnerabilityTable: document.getElementById('vulnerability-table'),
    searchInput: document.getElementById('search-vulnerabilities'),
    exportButton: document.getElementById('export-report'),
    modal: document.getElementById('vulnerability-modal'),
    closeModal: document.querySelector('.close-modal'),
    modalCloseBtn: document.getElementById('modal-close'),
    modalDeleteBtn: document.getElementById('modal-delete'),
    mobileMenuToggle: document.getElementById('mobile-menu-toggle'),
    mainNav: document.getElementById('main-nav')
};

// Mobile menu toggle
elements.mobileMenuToggle.addEventListener('click', () => {
    elements.mainNav.classList.toggle('active');
});

// Chart objects
let riskDistributionChart;
let cvssTimelineChart;
let impactDistributionChart;

// Current vulnerability assessments data
let vulnerabilityAssessments = [];

// Initialize the dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Load vulnerability assessments from local storage
    loadAssessments();
    
    // Initialize event listeners
    initEventListeners();
    
    // Render dashboard components
    renderDashboard();
});

/**
 * Load assessments from backend API and update dashboard
 */
async function loadAssessments() {
    try {
        // Fetch dashboard statistics
        const statsResponse = await fetch('/api/dashboard/stats');
        const statsData = await statsResponse.json();
        
        // Fetch assessment history
        const historyResponse = await fetch('/api/cvss/history');
        const historyData = await historyResponse.json();
        
        if (statsData.success && historyData.success) {
            // Update dashboard with backend data
            updateDashboardStats(statsData.stats);
            updateAssessmentsList(historyData.assessments);
            
            // Store assessments globally for other functions
            vulnerabilityAssessments = historyData.assessments;
        } else {
            throw new Error('Failed to fetch data from backend');
        }
        
    } catch (error) {
        console.error('Error loading assessments from backend:', error);
        console.log('Falling back to localStorage');
        
        // Fallback to localStorage
        try {
            vulnerabilityAssessments = JSON.parse(localStorage.getItem('vulnerabilityAssessments')) || [];
            vulnerabilityAssessments.sort((a, b) => new Date(b.date) - new Date(a.date));
        } catch (localError) {
            console.error('Error loading from localStorage:', localError);
            vulnerabilityAssessments = [];
        }
    }
}

/**
 * Initialize all event listeners
 */
function initEventListeners() {
    // Search functionality
    if (elements.searchInput) {
        elements.searchInput.addEventListener('input', handleSearch);
    }
    
    // Export report button
    if (elements.exportButton) {
        elements.exportButton.addEventListener('click', exportReport);
    }
    
    // Modal close buttons
    if (elements.closeModal) {
        elements.closeModal.addEventListener('click', closeVulnerabilityModal);
    }
    
    if (elements.modalCloseBtn) {
        elements.modalCloseBtn.addEventListener('click', closeVulnerabilityModal);
    }
    
    // Delete button in modal
    if (elements.modalDeleteBtn) {
        elements.modalDeleteBtn.addEventListener('click', deleteVulnerability);
    }
    
    // Mobile menu toggle
    if (elements.mobileMenuToggle) {
        elements.mobileMenuToggle.addEventListener('click', () => {
            elements.mainNav.classList.toggle('active');
        });
    }
    
    // Close mobile menu when clicking outside
    document.addEventListener('click', (event) => {
        if (elements.mainNav && elements.mainNav.classList.contains('active') && 
            !elements.mainNav.contains(event.target) && 
            event.target !== elements.mobileMenuToggle) {
            elements.mainNav.classList.remove('active');
        }
    });
}

/**
 * Render all dashboard components
 */
function renderDashboard() {
    updateSummaryCards();
    renderVulnerabilityTable();
    renderCharts();
}

/**
 * Update dashboard with statistics from backend
 * @param {Object} stats - Statistics from backend API
 */
function updateDashboardStats(stats) {
    // Update summary cards
    document.getElementById('total-vulnerabilities').textContent = stats.total_vulnerabilities;
    document.getElementById('average-cvss').textContent = stats.average_cvss_score;
    document.getElementById('highest-risk').textContent = stats.highest_risk;
    document.getElementById('risk-index').textContent = stats.risk_index;
    
    // Update risk distribution chart
    updateRiskDistributionChartWithData(stats.risk_distribution);
}

/**
 * Update risk distribution chart with backend data
 * @param {Object} riskDistribution - Risk distribution data
 */
function updateRiskDistributionChartWithData(riskDistribution) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    
    if (riskChart) {
        riskChart.destroy();
    }
    
    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [
                    riskDistribution.Low,
                    riskDistribution.Medium,
                    riskDistribution.High,
                    riskDistribution.Critical
                ],
                backgroundColor: [
                    '#10b981',
                    '#f59e0b',
                    '#ef4444',
                    '#dc2626'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

/**
 * Update assessments list from backend data
 * @param {Array} assessments - Assessments from backend API
 */
function updateAssessmentsList(assessments) {
    vulnerabilityAssessments = assessments;
    renderVulnerabilityTable();
    renderCharts();
}

/**
 * Update the summary cards with current data
 */
function updateSummaryCards() {
    if (vulnerabilityAssessments.length === 0) {
        elements.totalVulnerabilities.textContent = '0';
        elements.averageScore.textContent = '0.0';
        elements.highestRisk.textContent = 'None';
        elements.riskIndex.textContent = '0.0';
        return;
    }
    
    // Total vulnerabilities
    elements.totalVulnerabilities.textContent = vulnerabilityAssessments.length;
    
    // Average CVSS Score
    const avgScore = vulnerabilityAssessments.reduce((sum, item) => sum + item.baseScore, 0) / vulnerabilityAssessments.length;
    elements.averageScore.textContent = avgScore.toFixed(1);
    
    // Highest Risk
    const highestRisk = vulnerabilityAssessments.reduce((highest, item) => {
        return (item.rcs > highest.rcs) ? item : highest;
    }, vulnerabilityAssessments[0]);
    elements.highestRisk.textContent = highestRisk.riskCategory;
    
    // Overall Risk Index (weighted average of RCS scores)
    const riskIndex = vulnerabilityAssessments.reduce((sum, item) => sum + item.rcs, 0) / vulnerabilityAssessments.length;
    elements.riskIndex.textContent = riskIndex.toFixed(1);
}

/**
 * Render the vulnerability table
 * @param {Array} data - Optional filtered data to display
 */
function renderVulnerabilityTable(data = null) {
    const tableBody = elements.vulnerabilityTable.querySelector('tbody');
    const assessments = data || vulnerabilityAssessments;
    
    // Clear existing rows
    tableBody.innerHTML = '';
    
    if (assessments.length === 0) {
        // Show empty state
        const emptyRow = document.createElement('tr');
        emptyRow.className = 'empty-state';
        emptyRow.innerHTML = `
            <td colspan="7">
                <div class="empty-message">
                    <i class="fas fa-info-circle"></i>
                    <p>No vulnerability assessments found. Add assessments from the CVSS Prediction page.</p>
                </div>
            </td>
        `;
        tableBody.appendChild(emptyRow);
        return;
    }
    
    // Add rows for each assessment
    assessments.forEach((assessment, index) => {
        const row = document.createElement('tr');
        
        // Format date for display - handle both timestamp (backend) and date (localStorage) formats
        const dateValue = assessment.timestamp || assessment.date;
        const date = new Date(dateValue);
        const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        
        // Handle both backend and localStorage data structures
        const cwe = assessment.assessmentData ? assessment.assessmentData.cwe : assessment.cwe;
        const summary = assessment.assessmentData ? assessment.assessmentData.summary : assessment.summary;
        const baseScore = assessment.baseScore || assessment.cvss_score || assessment.cvssScore;
        const riskCategory = assessment.riskCategory || assessment.risk_category;
        
        // Truncate summary for table display
        const truncatedSummary = summary && summary.length > 100 
            ? summary.substring(0, 100) + '...' 
            : summary || 'No summary provided';
        
        row.innerHTML = `
            <td>${index + 1}</td>
            <td>CWE-${cwe || 'N/A'}</td>
            <td>${formattedDate}</td>
            <td>${truncatedSummary}</td>
            <td>${baseScore.toFixed(1)}</td>
            <td>
                <span class="risk-category risk-${riskCategory.toLowerCase()}">${riskCategory}</span>
            </td>
            <td>
                <button class="btn btn-secondary btn-sm view-details" data-id="${assessment.id}">
                    <i class="fas fa-eye"></i> View
                </button>
            </td>
        `;
        
        tableBody.appendChild(row);
        
        // Add event listener to view button
        const viewButton = row.querySelector('.view-details');
        viewButton.addEventListener('click', () => {
            openVulnerabilityModal(assessment.id);
        });
    });
}

/**
 * Render dashboard charts
 */
function renderCharts() {
    renderRiskDistributionChart();
    renderCVSSTrendChart();
    renderImpactDistributionChart();
}

/**
 * Render the risk distribution chart (pie chart)
 */
function renderRiskDistributionChart() {
    const ctx = document.getElementById('risk-distribution-chart').getContext('2d');
    
    // Count risk categories
    const riskCounts = {
        'Low': 0,
        'Medium': 0,
        'High': 0,
        'Critical': 0
    };
    
    vulnerabilityAssessments.forEach(assessment => {
        riskCounts[assessment.riskCategory]++;
    });
    
    // Destroy existing chart if it exists
    if (riskDistributionChart) {
        riskDistributionChart.destroy();
    }
    
    // Create new chart
    riskDistributionChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(riskCounts),
            datasets: [{
                data: Object.values(riskCounts),
                backgroundColor: [
                    'rgba(39, 174, 96, 0.7)',    // Low - Green
                    'rgba(243, 156, 18, 0.7)',   // Medium - Orange
                    'rgba(231, 76, 60, 0.7)',    // High - Red
                    'rgba(142, 68, 173, 0.7)'    // Critical - Purple
                ],
                borderColor: [
                    'rgba(39, 174, 96, 1)',
                    'rgba(243, 156, 18, 1)',
                    'rgba(231, 76, 60, 1)',
                    'rgba(142, 68, 173, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Render CVSS score timeline chart (line chart)
 */
function renderCVSSTrendChart() {
    const ctx = document.getElementById('cvss-trend-chart').getContext('2d');
    
    // Prepare data for timeline (last 10 assessments)
    const recentAssessments = [...vulnerabilityAssessments].slice(0, 10).reverse();
    
    const dates = recentAssessments.map(a => {
        const date = new Date(a.date);
        return date.toLocaleDateString();
    });
    
    const scores = recentAssessments.map(a => a.baseScore);
    const rcsScores = recentAssessments.map(a => a.rcs);
    
    // Destroy existing chart if it exists
    if (cvssTimelineChart) {
        cvssTimelineChart.destroy();
    }
    
    // Create new chart
    cvssTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'CVSS Base Score',
                    data: scores,
                    borderColor: 'rgba(44, 116, 179, 1)',
                    backgroundColor: 'rgba(44, 116, 179, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Risk Classification Score',
                    data: rcsScores,
                    borderColor: 'rgba(231, 76, 60, 1)',
                    backgroundColor: 'transparent',
                    borderDash: [5, 5],
                    tension: 0.4,
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 10,
                    title: {
                        display: true,
                        text: 'Score'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Date'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                }
            }
        }
    });
}

/**
 * Render impact distribution chart (bar chart)
 */
function renderImpactDistributionChart() {
    const ctx = document.getElementById('impact-distribution-chart').getContext('2d');
    
    // Calculate average scores for each impact metric
    let confidentialityTotal = 0;
    let integrityTotal = 0;
    let availabilityTotal = 0;
    
    vulnerabilityAssessments.forEach(assessment => {
        const metrics = assessment.assessmentData;
        
        // Map values to numeric scores for calculation (N=0, P=5, C=10)
        const valueMap = { 'N': 0, 'P': 5, 'C': 10 };
        
        confidentialityTotal += valueMap[metrics.confidentiality] || 0;
        integrityTotal += valueMap[metrics.integrity] || 0;
        availabilityTotal += valueMap[metrics.availability] || 0;
    });
    
    const count = vulnerabilityAssessments.length || 1; // Avoid division by zero
    
    const averages = [
        confidentialityTotal / count,
        integrityTotal / count,
        availabilityTotal / count
    ];
    
    // Destroy existing chart if it exists
    if (impactDistributionChart) {
        impactDistributionChart.destroy();
    }
    
    // Create new chart
    impactDistributionChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Confidentiality', 'Integrity', 'Availability'],
            datasets: [{
                label: 'Average Impact',
                data: averages,
                backgroundColor: [
                    'rgba(41, 128, 185, 0.7)',
                    'rgba(39, 174, 96, 0.7)',
                    'rgba(142, 68, 173, 0.7)'
                ],
                borderColor: [
                    'rgba(41, 128, 185, 1)',
                    'rgba(39, 174, 96, 1)',
                    'rgba(142, 68, 173, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 10,
                    title: {
                        display: true,
                        text: 'Average Impact (0-10)'
                    }
                }
            }
        }
    });
}

/**
 * Handle search functionality
 */
function handleSearch() {
    const searchTerm = elements.searchInput.value.toLowerCase();
    
    if (!searchTerm) {
        renderVulnerabilityTable(); // Reset to show all
        return;
    }
    
    // Filter assessments based on search term
    const filteredAssessments = vulnerabilityAssessments.filter(assessment => {
        return (
            assessment.assessmentData.cwe.toString().includes(searchTerm) ||
            assessment.assessmentData.summary.toLowerCase().includes(searchTerm) ||
            assessment.riskCategory.toLowerCase().includes(searchTerm) ||
            assessment.vectorString.toLowerCase().includes(searchTerm)
        );
    });
    
    renderVulnerabilityTable(filteredAssessments);
}

/**
 * Open the vulnerability detail modal
 * @param {string} id - The ID of the vulnerability to display
 */
function openVulnerabilityModal(id) {
    const assessment = vulnerabilityAssessments.find(a => a.id === id);
    
    if (!assessment) {
        alert('Vulnerability data not found');
        return;
    }
    
    // Populate modal with assessment data
    document.getElementById('modal-cwe').textContent = assessment.assessmentData.cwe;
    document.getElementById('modal-cvss-score').textContent = assessment.baseScore.toFixed(1);
    
    const riskCategoryEl = document.getElementById('modal-risk-category');
    riskCategoryEl.textContent = assessment.riskCategory;
    riskCategoryEl.className = `risk-category risk-${assessment.riskCategory.toLowerCase()}`;
    
    // Format date
    const date = new Date(assessment.date);
    document.getElementById('modal-date').textContent = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    
    document.getElementById('modal-summary').textContent = assessment.assessmentData.summary;
    
    // CVSS Metrics display
    const metrics = assessment.assessmentData;
    const metricFullNames = {
        'AV': { 'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical' },
        'AC': { 'L': 'Low', 'M': 'Medium', 'H': 'High' },
        'Au': { 'N': 'None', 'S': 'Single', 'M': 'Multiple' },
        'C': { 'N': 'None', 'P': 'Partial', 'C': 'Complete' },
        'I': { 'N': 'None', 'P': 'Partial', 'C': 'Complete' },
        'A': { 'N': 'None', 'P': 'Partial', 'C': 'Complete' }
    };
    
    document.getElementById('modal-av').textContent = metricFullNames['AV'][metrics.accessVector] || metrics.accessVector;
    document.getElementById('modal-ac').textContent = metricFullNames['AC'][metrics.accessComplexity] || metrics.accessComplexity;
    document.getElementById('modal-au').textContent = metricFullNames['Au'][metrics.authentication] || metrics.authentication;
    document.getElementById('modal-c').textContent = metricFullNames['C'][metrics.confidentiality] || metrics.confidentiality;
    document.getElementById('modal-i').textContent = metricFullNames['I'][metrics.integrity] || metrics.integrity;
    document.getElementById('modal-a').textContent = metricFullNames['A'][metrics.availability] || metrics.availability;
    
    // Weighted calculation breakdown
    document.getElementById('modal-exploitability').textContent = 
        ((assessment.exploitability / 20) * 10).toFixed(1) + ' × 0.3 = ' + 
        ((assessment.exploitability / 20) * 0.3 * 10).toFixed(1);
    
    document.getElementById('modal-impact').textContent = 
        ((assessment.impact / 10.41) * 10).toFixed(1) + ' × 0.5 = ' + 
        ((assessment.impact / 10.41) * 0.5 * 10).toFixed(1);
    
    document.getElementById('modal-vulnerability').textContent = 
        (assessment.vulnerabilityAnalysis * 10).toFixed(1) + ' × 0.2 = ' + 
        (assessment.vulnerabilityAnalysis * 0.2 * 10).toFixed(1);
    
    document.getElementById('modal-rcs').textContent = assessment.rcs.toFixed(1);
    
    // Store the current vulnerability ID for delete functionality
    elements.modalDeleteBtn.dataset.id = id;
    
    // Show the modal
    elements.modal.style.display = 'block';
}

/**
 * Close the vulnerability detail modal
 */
function closeVulnerabilityModal() {
    elements.modal.style.display = 'none';
}

/**
 * Delete a vulnerability assessment
 */
function deleteVulnerability() {
    const id = elements.modalDeleteBtn.dataset.id;
    
    if (!id) return;
    
    // Confirm deletion
    if (!confirm('Are you sure you want to delete this vulnerability assessment?')) {
        return;
    }
    
    // Remove assessment from array
    vulnerabilityAssessments = vulnerabilityAssessments.filter(a => a.id !== id);
    
    // Update local storage
    localStorage.setItem('vulnerabilityAssessments', JSON.stringify(vulnerabilityAssessments));
    
    // Close modal
    closeVulnerabilityModal();
    
    // Refresh dashboard
    renderDashboard();
}

/**
 * Export vulnerability assessment report as PDF
 */
function exportReport() {
    // Check if there are assessments to export
    if (vulnerabilityAssessments.length === 0) {
        alert('No vulnerability assessments to export.');
        return;
    }
    
    // Reference to jsPDF library
    const { jsPDF } = window.jspdf;
    
    // Create new PDF document
    const doc = new jsPDF();
    
    // Add title and date
    doc.setFontSize(18);
    doc.text('CVSS Risk Assessment Report', 14, 22);
    
    doc.setFontSize(11);
    doc.text(`Generated: ${new Date().toLocaleDateString()}`, 14, 30);
    
    // Add summary information
    doc.setFontSize(14);
    doc.text('Summary', 14, 40);
    
    doc.setFontSize(10);
    const avgScore = vulnerabilityAssessments.reduce((sum, item) => sum + item.baseScore, 0) / vulnerabilityAssessments.length;
    const riskIndex = vulnerabilityAssessments.reduce((sum, item) => sum + item.rcs, 0) / vulnerabilityAssessments.length;
    
    doc.text(`Total Vulnerabilities: ${vulnerabilityAssessments.length}`, 14, 50);
    doc.text(`Average CVSS Score: ${avgScore.toFixed(1)}`, 14, 56);
    doc.text(`Overall Risk Index: ${riskIndex.toFixed(1)}`, 14, 62);
    
    // Risk distribution
    const riskCounts = {
        'Critical': vulnerabilityAssessments.filter(a => a.riskCategory === 'Critical').length,
        'High': vulnerabilityAssessments.filter(a => a.riskCategory === 'High').length,
        'Medium': vulnerabilityAssessments.filter(a => a.riskCategory === 'Medium').length,
        'Low': vulnerabilityAssessments.filter(a => a.riskCategory === 'Low').length
    };
    
    doc.text('Risk Distribution:', 14, 72);
    doc.text(`Critical: ${riskCounts.Critical}`, 20, 78);
    doc.text(`High: ${riskCounts.High}`, 20, 84);
    doc.text(`Medium: ${riskCounts.Medium}`, 20, 90);
    doc.text(`Low: ${riskCounts.Low}`, 20, 96);
    
    // Add vulnerability table
    doc.setFontSize(14);
    doc.text('Vulnerability Assessments', 14, 110);
    
    // Prepare table data
    const tableData = vulnerabilityAssessments.map((assessment, index) => {
        const date = new Date(assessment.date);
        const formattedDate = date.toLocaleDateString();
        
        return [
            index + 1,
            `CWE-${assessment.assessmentData.cwe}`,
            formattedDate,
            assessment.baseScore.toFixed(1),
            assessment.riskCategory,
            assessment.rcs.toFixed(1)
        ];
    });
    
    // Add table to PDF using AutoTable plugin
    doc.autoTable({
        startY: 115,
        head: [['#', 'CWE', 'Date', 'CVSS Score', 'Risk Category', 'RCS']],
        body: tableData,
        theme: 'striped',
        headStyles: {
            fillColor: [44, 116, 179]
        },
        columnStyles: {
            0: { cellWidth: 15 },
            1: { cellWidth: 25 },
            2: { cellWidth: 30 },
            3: { cellWidth: 30 },
            4: { cellWidth: 30 },
            5: { cellWidth: 30 }
        }
    });
    
    // Add weighted model explanation
    const finalY = doc.lastAutoTable.finalY + 10;
    
    if (finalY > 250) {
        doc.addPage();
        doc.setFontSize(14);
        doc.text('Risk Classification Model', 14, 20);
        
        doc.setFontSize(10);
        doc.text('The Risk Classification Score (RCS) is computed using a weighted model:', 14, 30);
        doc.text('• Exploitability Metrics: 30% weight', 14, 40);
        doc.text('• Impact Metrics: 50% weight', 14, 46);
        doc.text('• Vulnerability Summary Analysis: 20% weight', 14, 52);
        
        doc.text('Risk Classification Thresholds:', 14, 62);
        doc.text('• Low Risk: RCS < 3.5', 14, 68);
        doc.text('• Medium Risk: 3.5 ≤ RCS < 6.5', 14, 74);
        doc.text('• High Risk: 6.5 ≤ RCS < 8.5', 14, 80);
        doc.text('• Critical Risk: RCS ≥ 8.5', 14, 86);
    } else {
        doc.setFontSize(14);
        doc.text('Risk Classification Model', 14, finalY);
        
        doc.setFontSize(10);
        doc.text('The Risk Classification Score (RCS) is computed using a weighted model:', 14, finalY + 10);
        doc.text('• Exploitability Metrics: 30% weight', 14, finalY + 20);
        doc.text('• Impact Metrics: 50% weight', 14, finalY + 26);
        doc.text('• Vulnerability Summary Analysis: 20% weight', 14, finalY + 32);
        
        doc.text('Risk Classification Thresholds:', 14, finalY + 42);
        doc.text('• Low Risk: RCS < 3.5', 14, finalY + 48);
        doc.text('• Medium Risk: 3.5 ≤ RCS < 6.5', 14, finalY + 54);
        doc.text('• High Risk: 6.5 ≤ RCS < 8.5', 14, finalY + 60);
        doc.text('• Critical Risk: RCS ≥ 8.5', 14, finalY + 66);
    }
    
    // Save the PDF
    doc.save('cvss-risk-assessment-report.pdf');
}

// Handle click events outside the modal to close it
window.addEventListener('click', (event) => {
    if (event.target === elements.modal) {
        closeVulnerabilityModal();
    }
});
