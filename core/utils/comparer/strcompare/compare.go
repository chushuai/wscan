/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package strcompare

type StringArrayComparer struct {
	strA []string
	strB []string
}

// 在 Ratio 方法中，我们首先检查两个字符串数组是否都为空，如果是，则它们的相似度为 1（因为它们没有任何不同之处）。如果其中一个为空，则相似度为 0（因为它们没有共同之处）。
func (sac *StringArrayComparer) Ratio() float32 {
	if len(sac.strA) == 0 && len(sac.strB) == 0 {
		return 1
	}
	if len(sac.strA) == 0 || len(sac.strB) == 0 {
		return 0
	}

	setA := make(map[string]bool)
	setB := make(map[string]bool)

	for _, s := range sac.strA {
		setA[s] = true
	}

	for _, s := range sac.strB {
		setB[s] = true
	}

	var count float32
	for s := range setA {
		if setB[s] {
			count++
		}
	}

	return count / (float32(len(setA)+len(setB)) - count)
}

func NewStringArrayComparer(strA, strB []string) *StringArrayComparer {
	return &StringArrayComparer{
		strA: strA,
		strB: strB,
	}
}
