<?php

namespace App\Charts;

use App\Models\Position;
use ArielMejiaDev\LarapexCharts\LarapexChart;

class EmployeesChart
{
    protected $chart;

    public function __construct(LarapexChart $chart)
    {
        $this->chart = $chart;
    }

    public function build(): \ArielMejiaDev\LarapexCharts\BarChart
{
     $positions = Position::withCount('employees')->get();
     $positionsLabels = $positions->pluck('name')->toArray();
     $employeesCount = $positions->pluck('employees_count')->toArray();
     return $this->chart->barChart()
    ->addData('Jumlah Karyawan', $employeesCount)
    ->setTitle('Posisi')
    ->setSubtitle('Posisi dengan Jumlah Karyawan Terbanyak')
    ->setXAxis($positionsLabels);
}

}
