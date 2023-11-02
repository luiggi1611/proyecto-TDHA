/*=========================================================================================
    File Name: funnel-plot.js
    Description: echarts funnel plot chart
    ----------------------------------------------------------------------------------------
    Item Name: Modern Admin - Clean Bootstrap 4 Dashboard HTML Template
    Version: 1.0
    Author: PIXINVENT
    Author URL: http://www.themeforest.net/user/pixinvent
==========================================================================================*/

// Basic funnel plot chart
// ------------------------------
$(window).on("load", function(){

    // Set paths
    // ------------------------------

    require.config({
        paths: {
            echarts: '../../../static/app-assets/vendors/js/charts/echarts'
        }
    });


    // Configuration
    // ------------------------------

    require(
        [
            'echarts',
            'echarts/chart/funnel',
            'echarts/chart/gauge'
        ],


        // Charts setup
        function (ec) {

            // Initialize chart
            // ------------------------------
            var myChart = ec.init(document.getElementById('funnel-plot'));

            // Chart Options
            // ------------------------------
            chartOptions = {

                // Add tooltip
                tooltip : {
                    trigger: 'item',
                    formatter: "{a} <br/>{b} : {c}%"
                },

     

    
         
                // Add legend
                legend: {
                    data : ['Work','Eat','Commute','Watch TV','Sleep']
                },

                // Add Custom Colors
                color: ['#00A5A8', '#626E82', '#FF7D4D','#FF4558', '#28D094'],

                // Enable drag recalculate
                calculable: true,

                // Add series
                series : [
                    {
                        name: 'Funnel',
                        type: 'funnel',
                        left: '10%',
                        top: 60,
                        bottom: 60,
                        width: '80%',
                        min: 0,
                        max: 100,
                        minSize: '0%',
                        maxSize: '100%',
                        sort: 'descending',
                        gap: 2,
                        label: {
                          show: true,
                          position: 'inside'
                        },
                        labelLine: {
                          length: 10,
                          lineStyle: {
                            width: 1,
                            type: 'solid'
                          }
                        },
                        itemStyle: {
                          borderColor: '#fff',
                          borderWidth: 1
                        },
                        emphasis: {
                          label: {
                            fontSize: 20
                          }
                        },
                        // width: '40%',
                        data:[
                            {value:60, name:'Democratizar  la cultura de datos en el BN'},
                            {value:40, name:'Desarrollar Modelos avanzados de Analitica'},
                            {value:20, name:'Resolver problemas con Datos'},
                            {value:80, name:'Generar valor agregado explotando los datos'},
                            {value:100, name:'Trabajar con agilidad'}
                        ]
                    }
                ]
            };

            // Apply options
            // ------------------------------

            myChart.setOption(chartOptions);



            // Resize chart
            // ------------------------------

            $(function () {

                // Resize chart on menu width change and window resize
                $(window).on('resize', resize);
                $(".menu-toggle").on('click', resize);

                // Resize function
                function resize() {
                    setTimeout(function() {

                        // Resize chart
                        myChart.resize();
                    }, 200);
                }
            });
        }
    );
});