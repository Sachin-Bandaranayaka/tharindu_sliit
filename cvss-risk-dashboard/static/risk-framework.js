
// Risk Framework Constants
const WEIGHTS = {
    CVSS: 0.40,
    BUSINESS: 0.25,
    ASSET: 0.15,
    THREAT: 0.10,
    MITIGATION: 0.10
};

const RISK_LEVELS = {
    LOW: { 
        max: 3.5, 
        label: 'Low Risk', 
        color: '#2ecc71',
        recommendations: [
            'Monitor through regular security assessments',
            'Document in risk register',
            'Review in quarterly security meetings'
        ]
    },
    MEDIUM: { 
        max: 6.5, 
        label: 'Medium Risk', 
        color: '#f1c40f',
        recommendations: [
            'Develop mitigation plan within 3 months',
            'Increase monitoring frequency',
            'Review security controls monthly'
        ]
    },
    HIGH: { 
        max: 8.5, 
        label: 'High Risk', 
        color: '#e67e22',
        recommendations: [
            'Immediate mitigation planning required',
            'Weekly progress reviews',
            'Consider temporary controls'
        ]
    },
    CRITICAL: { 
        max: 10, 
        label: 'Critical Risk', 
        color: '#e74c3c',
        recommendations: [
            'Immediate executive attention required',
            'Daily progress tracking',
            'Emergency response team activation'
        ]
    }
};

// DOM Elements
const elements = {
    form: document.getElementById('risk-framework-form'),
    cvssScore: document.getElementById('cvss-score'),
    businessImpact: document.getElementById('business-impact'),
    assetValue: document.getElementById('asset-value'),
    threatLikelihood: document.getElementById('threat-likelihood'),
    mitigationEffectiveness: document.getElementById('mitigation-effectiveness'),
    riskMeter: document.getElementById('risk-meter'),
    finalRiskScore: document.getElementById('final-risk-score'),
    finalRiskCategory: document.getElementById('final-risk-category'),
    cvssContribution: document.getElementById('cvss-contribution'),
    businessContribution: document.getElementById('business-contribution'),
    assetContribution: document.getElementById('asset-contribution'),
    threatContribution: document.getElementById('threat-contribution'),
    mitigationContribution: document.getElementById('mitigation-contribution'),
    recommendations: document.getElementById('risk-recommendations'),
    mobileMenuToggle: document.getElementById('mobile-menu-toggle'),
    mainNav: document.getElementById('main-nav')
};

// Risk Assessment History
let riskAssessmentHistory = JSON.parse(localStorage.getItem('riskAssessmentHistory') || '[]');

function saveAssessmentToHistory(assessment) {
    const historyItem = {
        ...assessment,
        date: new Date().toISOString(),
        id: Date.now()
    };
    riskAssessmentHistory.unshift(historyItem);
    localStorage.setItem('riskAssessmentHistory', JSON.stringify(riskAssessmentHistory.slice(0, 10)));
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    elements.form.addEventListener('submit', handleRiskAssessment);
    elements.mobileMenuToggle.addEventListener('click', toggleMobileMenu);
    displayRiskHistory();
});

function handleRiskAssessment(event) {
    event.preventDefault();
    
    const cvssScore = parseFloat(elements.cvssScore.value);
    const businessImpact = parseInt(elements.businessImpact.value);
    const assetValue = parseInt(elements.assetValue.value);
    const threatLikelihood = parseInt(elements.threatLikelihood.value);
    const mitigationEffectiveness = parseInt(elements.mitigationEffectiveness.value);

    const normalizedBusinessImpact = (businessImpact / 5) * 10;
    const normalizedAssetValue = (assetValue / 5) * 10;
    const normalizedThreatLikelihood = (threatLikelihood / 5) * 10;
    const normalizedMitigation = (mitigationEffectiveness / 5) * 10;

    const weightedScore = calculateWeightedScore(
        cvssScore,
        normalizedBusinessImpact,
        normalizedAssetValue,
        normalizedThreatLikelihood,
        normalizedMitigation
    );

    updateUI(weightedScore, {
        cvss: cvssScore * WEIGHTS.CVSS,
        business: normalizedBusinessImpact * WEIGHTS.BUSINESS,
        asset: normalizedAssetValue * WEIGHTS.ASSET,
        threat: normalizedThreatLikelihood * WEIGHTS.THREAT,
        mitigation: normalizedMitigation * WEIGHTS.MITIGATION
    });
}

function calculateWeightedScore(cvss, business, asset, threat, mitigation) {
    return (
        cvss * WEIGHTS.CVSS +
        business * WEIGHTS.BUSINESS +
        asset * WEIGHTS.ASSET +
        threat * WEIGHTS.THREAT +
        mitigation * WEIGHTS.MITIGATION
    );
}

function getRiskLevel(score) {
    if (score < RISK_LEVELS.LOW.max) return RISK_LEVELS.LOW;
    if (score < RISK_LEVELS.MEDIUM.max) return RISK_LEVELS.MEDIUM;
    if (score < RISK_LEVELS.HIGH.max) return RISK_LEVELS.HIGH;
    return RISK_LEVELS.CRITICAL;
}

function updateUI(finalScore, contributions) {
    const riskLevel = getRiskLevel(finalScore);
    
    // Update meter and score display
    elements.riskMeter.style.width = `${(finalScore / 10) * 100}%`;
    elements.riskMeter.style.backgroundColor = riskLevel.color;
    elements.finalRiskScore.textContent = finalScore.toFixed(2);
    elements.finalRiskCategory.textContent = riskLevel.label;
    elements.finalRiskCategory.style.color = riskLevel.color;

    // Update contribution values
    elements.cvssContribution.textContent = contributions.cvss.toFixed(2);
    elements.businessContribution.textContent = contributions.business.toFixed(2);
    elements.assetContribution.textContent = contributions.asset.toFixed(2);
    elements.threatContribution.textContent = contributions.threat.toFixed(2);
    elements.mitigationContribution.textContent = contributions.mitigation.toFixed(2);

    // Generate and display recommendations
    generateRecommendations(finalScore, contributions);
}

function generateRecommendations(score, contributions) {
    const recommendations = [];
    
    if (contributions.cvss > 3) {
        recommendations.push('High CVSS score indicates critical technical vulnerabilities that need immediate attention.');
    }
    
    if (contributions.business > 2) {
        recommendations.push('Consider implementing additional business continuity measures.');
    }
    
    if (contributions.asset > 1.5) {
        recommendations.push('High-value assets detected. Review access controls and monitoring.');
    }
    
    if (contributions.threat > 1) {
        recommendations.push('Elevated threat likelihood. Enhance threat monitoring and detection capabilities.');
    }
    
    if (contributions.mitigation < 0.5) {
        recommendations.push('Strengthen existing security controls and mitigation measures.');
    }

    elements.recommendations.innerHTML = `
        <h4>Recommendations</h4>
        <ul>
            ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
        </ul>
    `;
}

function toggleMobileMenu() {
    elements.mainNav.classList.toggle('active');
}
