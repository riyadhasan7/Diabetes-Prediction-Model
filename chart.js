<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<canvas id="diabetesChart"></canvas>
<script>
    const ctx = document.getElementById('diabetesChart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Age', 'BMI', 'HbA1c Level', 'Blood Glucose'],
            datasets: [{
                label: 'Risk Factor',
                data: [30, 27, 7.1, 180],
                backgroundColor: ['blue', 'red', 'green', 'orange']
            }]
        }
    });
</script>
