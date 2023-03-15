/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import "math"

type Probability struct {
	Input []float64
}

func (p *Probability) Avg() float64 {
	if len(p.Input) == 0 {
		return 0
	}
	sum := p.Sum()
	return sum / float64(len(p.Input))
}

func (p *Probability) StdDev() float64 {
	if len(p.Input) <= 1 {
		return 0
	}
	avg := p.Avg()
	variance := 0.0
	for _, x := range p.Input {
		variance += math.Pow(x-avg, 2)
	}
	variance /= float64(len(p.Input) - 1)
	return math.Sqrt(variance)
}

func (p *Probability) Sum() float64 {
	sum := 0.0
	for _, x := range p.Input {
		sum += x
	}
	return sum
}
