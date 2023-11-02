/*=========================================================================================
    File Name: right-align-funnel.js
    Description: echarts right align funnel chart
    ----------------------------------------------------------------------------------------
    Item Name: Modern Admin - Clean Bootstrap 4 Dashboard HTML Template
    Version: 1.0
    Author: PIXINVENT
    Author URL: http://www.themeforest.net/user/pixinvent
==========================================================================================*/

// Right align funnel chart
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
            var myChart = ec.init(document.getElementById('right-align-funnel'));

            // Chart Options
            // ------------------------------
            chartOptions = {
                title: {
                    text: 'Nuestros Objetivos'
                  },
                // Add tooltip
                tooltip: {
                    trigger: 'item',
                    //formatter: "{a} <br/>{b}: {c}%"
                },

                // Add legend
               // legend: {
               //     orient: 'vertical',
               //     x: 'left',
               //     y: 75,
               //     data: ['Work','Eat','Commute','Watch TV','Sleep']
              //  },

                // Add Custom Colors
                color: ['#00A5A8', '#626E82', '#FF7D4D','#FF4558', '#28D094'],

                // Enable drag recalculate
                calculable: true,

                // Add series
                series: [
                    {
                        name: '',
                        type: 'funnel',
                        funnelAlign: 'right',
                        x: '25%',
                        x2: '25%',
                        y: '17.5%',
                        width: '50%',
                        height: '80%',
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
                        itemStyle: {
                            normal: {
                                label: {
                                    position: 'left'
                                }
                            }
                        },
                        data: [
                            {value:50, name:'Democratizar  la cultura de datos en el BN'},
                            {value:20, name:'Desarrollar Modelos avanzados de Analitica'},
                            {value:30, name:'Resolver problemas con Datos'},
                            {value:40, name:'Generar valor agregado explotando los datos'},
                            {value:10, name:'Trabajar con agilidad'}
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