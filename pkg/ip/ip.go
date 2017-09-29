// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"bytes"
	"fmt"
	"net"
	"sort"
)

const (
	ipv4BitLen = 8 * net.IPv4len
	ipv6BitLen = 8 * net.IPv6len
)

var ipv4Ipv6Slice = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}

// Implementation of sorting of a list of IP networks by the size of their masks.
type ByMask []*net.IPNet

func (s ByMask) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ByMask) Less(i, j int) bool {
	iPrefixSize, _ := s[i].Mask.Size()
	jPrefixSize, _ := s[j].Mask.Size()
	if iPrefixSize == jPrefixSize {
		byteArrComp := bytes.Compare(s[i].IP, s[j].IP)
		if byteArrComp < 0 {
			return true
		} else {
			return false
		}
	}
	return iPrefixSize < jPrefixSize
}

func (s ByMask) Len() int {
	return len(s)
}

// RemoveCIDRs removes the specified CIDRs from another set of CIDRs. If a CIDR to remove is not
// contained within the CIDR, the CIDR to remove is ignored. A slice of CIDRs is
// returned which contains the set of CIDRs provided minus the set of CIDRs which
// were removed.
func RemoveCIDRs(allowCIDRs, removeCIDRs []*net.IPNet) (*[]*net.IPNet, error) {

	// Ensure that we iterate through the provided CIDRs in order of largest
	// subnet first.
	sort.Sort(ByMask(removeCIDRs))

PreLoop:
	// Remove CIDRs which are contained within CIDRs that we want to remove;
	// such CIDRs are redundant.
	for j, removeCIDR := range removeCIDRs {
		for i, removeCIDR2 := range removeCIDRs {
			if i == j {
				continue
			}
			if removeCIDR.Contains(removeCIDR2.IP) {
				removeCIDRs = append(removeCIDRs[:i], removeCIDRs[i+1:]...)
				// Re-trigger loop since we have modified the slice we are iterating over.
				goto PreLoop
			}
		}
	}

Loop:
	for j, remove := range removeCIDRs {
		for i, allowCIDR := range allowCIDRs {

			// Don't allow comparison of different address spaces.
			if allowCIDR.IP.To4() != nil && remove.IP.To4() == nil || allowCIDR.IP.To4() == nil && remove.IP.To4() != nil {
				return nil, fmt.Errorf("cannot compare different address spaces")
			}

			// Only remove CIDR if it is contained in the subnet we are allowing.
			if allowCIDR.Contains(remove.IP) {
				nets, err := removeCIDR(allowCIDR, remove)
				if err != nil {
					return nil, err
				}

				// Remove CIDR that we have just processed and append new CIDRs
				// that we computed from removing the CIDR to remove.
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				allowCIDRs = append(allowCIDRs, nets...)
				goto Loop
			} else if remove.Contains(allowCIDR.IP.Mask(allowCIDR.Mask)) {
				// If a CIDR that we want to remove contains a CIDR in the list
				// that is allowed, then we can just remove the CIDR to allow.
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				goto Loop
			}
		}
		removeCIDRs = append(removeCIDRs[:j], removeCIDRs[j+1:]...)
		goto Loop
	}

	return &allowCIDRs, nil
}

func getFirstIP(ipNet *net.IPNet) *net.IP {
	//var mask, newIP net.IP
	var mask net.IP

	if ipNet.IP.To4() == nil {
		mask = make(net.IP, net.IPv6len)
		for i := 0; i < len(ipNet.Mask); i++ {
			mask[net.IPv6len-i-1] = ipNet.IP[net.IPv6len-i-1] & ^ipNet.Mask[i]
		}
	} else {
		mask = make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			mask[net.IPv4len-i-1] = ipNet.IP[net.IPv6len-i-1] & ^ipNet.Mask[i]
		}
	}

	/*for k := range *mask {
		(newIP)[k] = (*allowFirstIP)[k] | (*newIP)[k]
	}*/

	return &mask
}

func removeCIDR(allowCIDR, removeCIDR *net.IPNet) ([]*net.IPNet, error) {
	var allows []*net.IPNet
	var allowIsIpv4, removeIsIpv4 bool
	var allowBitLen int

	if allowCIDR.IP.To4() != nil {
		allowIsIpv4 = true
		allowBitLen = ipv4BitLen
	} else {
		allowBitLen = ipv6BitLen
	}

	if removeCIDR.IP.To4() != nil {
		removeIsIpv4 = true
	}

	if (removeIsIpv4 && !allowIsIpv4) || (!removeIsIpv4 && allowIsIpv4) {
		return nil, fmt.Errorf("cannot mix different address spaces")
	}

	// Get size of each CIDR mask.
	allowSize, _ := allowCIDR.Mask.Size()
	removeSize, _ := removeCIDR.Mask.Size()

	if allowSize >= removeSize {
		return nil, fmt.Errorf("allow CIDR must be a superset of remove CIDR")
	}

	allowFirstIPMasked := allowCIDR.IP.Mask(allowCIDR.Mask)
	removeFirstIPMasked := removeCIDR.IP.Mask(removeCIDR.Mask)

	// Convert to IPv4 in IPv6 addresses if needed.
	if allowIsIpv4 {
		allowFirstIPMasked = append(ipv4Ipv6Slice, allowFirstIPMasked...)
	}

	if removeIsIpv4 {
		removeFirstIPMasked = append(ipv4Ipv6Slice, removeFirstIPMasked...)
	}

	allowFirstIP := &allowFirstIPMasked
	removeFirstIP := &removeFirstIPMasked

	// Create CIDR's with mask size of Y+1, Y+2 ... X where Y is the mask length of the CIDR B
	// from which we are exluding a CIDR A with mask length X.
	for i := (allowBitLen - allowSize - 1); i >= (allowBitLen - removeSize); i-- {
		// The mask for each CIDR is simply the ith bit flipped, and then zero'ing
		// out all subsequent bits.
		newMaskSize := allowBitLen - i
		newIP := (*net.IP)(flipNthBit((*[]byte)(removeFirstIP), uint(i)))
		for k := range *allowFirstIP {
			(*newIP)[k] = (*allowFirstIP)[k] | (*newIP)[k]
		}

		newMask := net.CIDRMask(newMaskSize, allowBitLen)
		newIPMasked := newIP.Mask(newMask)

		newIpNet := net.IPNet{IP: newIPMasked, Mask: newMask}
		allows = append(allows, &newIpNet)
	}

	return allows, nil
}

// CoalesceCIDRs transforms the provided list of CIDRs into the most-minimal equivalent set of CIDRs.
// It removes CIDRs that are subnets of other CIDRs in the list, and groups together CIDRs that have the same mask size
// into a CIDR of the same mask size provided that they share the same number of most significant mask-size bits.
//
// All IPs should be of the same type (IPv4, IPv6).
func CoalesceCIDRs(cidrs []*net.IPNet) []*net.IPNet {
	// TODO: sort IPs
	//sort.Sort(ByMask(cidrs))

	//var transformedCIDRs []*net.IPNet

	cidrs = []*net.IPNet{{IP: net.ParseIP("10.32.0.30"), Mask: net.CIDRMask(30, ipv4BitLen)},
		{IP: net.ParseIP("10.32.0.30"), Mask: net.CIDRMask(32, ipv4BitLen)},
		//{IP: net.ParseIP("10.32.0.255"), Mask: net.CIDRMask(30, ipv4BitLen)},
		//{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, ipv4BitLen)},
		}

	var newCIDRs []*net.IPNet
	fmt.Printf("cidrs: %s\n", cidrs)

	for i:= len(cidrs) - 1; i > 0; i-- {
		ipNet := cidrs[i]
		ipNet1 := cidrs[i-1]

		previousIP := getPreviousIP(ipNet.IP)
		nextIP := getNextIP(ipNet.IP)

		fmt.Printf("previousIP: %s\n", previousIP)
		fmt.Printf("nextIP: %s\n", nextIP)
		fmt.Printf("ip: %s\n", ipNet.IP)

		firstIP, lastIP := ipNetToRange(*ipNet)
		fmt.Printf("firstIP: %s\n", firstIP)
		fmt.Printf("lastIP: %s\n", lastIP)
		fmt.Println()

		previousIP1 := getPreviousIP(ipNet1.IP)
		nextIP1 := getNextIP(ipNet1.IP)

		fmt.Printf("previousIP1: %s\n", previousIP1)
		fmt.Printf("nextIP1: %s\n", nextIP1)
		fmt.Printf("ip1: %s\n", ipNet1.IP)

		firstIP1, lastIP1 := ipNetToRange(*ipNet1)
		fmt.Printf("firstIP1: %s\n", firstIP1)
		fmt.Printf("firstIP1: %08b\n", firstIP1)
		fmt.Printf("lastIP1: %s\n", lastIP1)

		fmt.Printf("lastIP1: %08b\n", lastIP1)
		fmt.Println()

		if bytes.Compare(previousIP, lastIP1) <= 0 {
			fmt.Printf("%s <= %s\n", previousIP, lastIP1)
		}


		// Set first IP to minimum of the first IPs that we have sorted.
		var firstRangeIP net.IP
		if bytes.Compare(firstIP1, firstIP) <= 0 {
			firstRangeIP = firstIP1
		} else {
			firstRangeIP = firstIP
		}

		newRange := IPRange{First: firstRangeIP, Last: lastIP}
		fmt.Printf("newRange: %s\n", newRange)

		_ = createSpanningCIDR(newRange)
		//splitRange4(net.ParseIP("0.0.0.0"), 0, newRange.First, newRange.Last, &newCIDRs)
		fmt.Printf("newCIDRs: %s\n", newCIDRs)


		fmt.Println()
	}
PreLoop:
// Remove CIDRs which are contained within CIDRs that are in the list;
// such CIDRs are redundant.
	for j, cidr := range cidrs {
		for i, compareCIDR := range cidrs {
			if i == j {
				continue
			}
			cidrMaskSize, _ := cidr.Mask.Size()
			compareCIDRMaskSize, _ := compareCIDR.Mask.Size()
			if cidrMaskSize == compareCIDRMaskSize {

			}

			if cidr.Contains(compareCIDR.IP) {
				cidrs = append(cidrs[:i], cidrs[i+1:]...)
				// Re-trigger loop since we have modified the slice we are iterating over.
				goto PreLoop
			}
		}
	}
	return nil
}

func compareIPs(low, high net.IP) int {
	fmt.Printf("low: %08b\n", low)
	fmt.Printf("high: %08b\n", high)
	for i, _ := range high {
		fmt.Printf("low[%d], high[%d]: %d, %d\n", low[i], high[i])
		if low[i] == high[i] {
			fmt.Printf("low[%d] == high[%d]: %d\n", i, i, low[i])
			continue
		}
		if low[i] > high[i] {
			return 1
		} else {
			return -1
		}
	}
	return 0
}

func createSpanningCIDR(r IPRange) net.IPNet {
	highest := r.Last
	lowest := r.First
	fmt.Printf("highest: %s\n", highest)
	fmt.Printf("lowest: %s\n", lowest)
	fmt.Printf("compareIPs: %s, %s: %d\n", lowest, highest, compareIPs(lowest, highest))
	prefixLen := 32
	fmt.Printf("bytes.Compare(%s, %s) <= 0 : %v\n", lowest, highest, bytes.Compare(lowest, highest))
	for ; prefixLen > 0 && bytes.Compare(lowest, highest) <= 0 ; prefixLen-- {
		fmt.Printf("bytes.Compare(%s, %s) > 0 : %v\n", lowest, highest, bytes.Compare(lowest, highest))
		//fmt.Printf("prefixLen: %d\n", prefixLen)
		//fmt.Printf("highest before: %08b\n", highest)
		//fmt.Printf("len(highst): %d\n", len(highest))
		// iterate over each byte
		for i := (len(highest) - 1); i >= net.IPv6len - net.IPv4len + prefixLen % 8 ; i-- {
			//fmt.Printf("\thighest before: %08b\n", highest)
			//fmt.Printf("\t-1<<(8-uint(i mod 8): %d\n", (1<<(8-uint(i%8))))
			//fmt.Printf("8-uint(i mod 8): %d\n", 8-uint(i%8))
			// iterate over each bit
			for j := 0; j < prefixLen%8 ; j++ {
				fmt.Printf("\thighest before: %08b\n", highest)
				highest[i] &= -(1 << (8 - uint(j)))
				fmt.Printf("\thighest after: \t%08b\n", highest)
			}
		}
		fmt.Printf("highest after: %08b\n", highest)
	}
	fmt.Printf("highest: %s\n", highest)
	fmt.Printf("prefixlen: %d\n", prefixLen)

	return net.IPNet{}
}

// splitRange4 recursively computes the CIDR blocks to cover the range lo to hi.
func splitRange4(addr net.IP, prefix uint, lo, hi net.IP, cidrs *[]*net.IPNet) error {
	if prefix > 32 {
		return fmt.Errorf("Invalid mask size: %d", prefix)
	}

	_, bc := ipNetToRange(net.IPNet{IP: addr, Mask: net.CIDRMask(int(prefix), 8*net.IPv4len)})
	fmt.Printf("bc: %s\n", bc)
	if (bytes.Compare(lo, addr) < 0 || bytes.Compare(hi, bc) > 0) {
		return fmt.Errorf("%s, %s out of range for network %s/%d, broadcast %s", lo, hi, addr, prefix, bc)
	}

	fmt.Printf("lo: %s\n", lo)
	fmt.Printf("addr: %s\n", addr)
	fmt.Printf("hi: %s\n", hi)
	if (bytes.Equal(lo, addr) && bytes.Equal(hi, bc)) {
		cidr := net.IPNet{IP: addr, Mask: net.CIDRMask(int(prefix), 8*net.IPv4len)}
		fmt.Printf("cidr: %s\n", cidr)
		*cidrs = append(*cidrs, &cidr)
		return nil
	}

	prefix++
	lowerHalf := addr
	fmt.Printf("lowerHalf: %s\n", addr)
	nthBitIp := ([]byte)(addr)
	upperHalf := setNthBit(&nthBitIp, prefix, 1)
	fmt.Printf("upperHalf: %s\n", addr)
	if bytes.Compare(hi, *upperHalf) < 0 {
		return splitRange4(lowerHalf, prefix, lo, hi, cidrs)
	} else if bytes.Compare(lo, *upperHalf) >= 0 {
		return splitRange4(*upperHalf, prefix, lo, hi, cidrs)
	} else {
		_, broad := ipNetToRange(net.IPNet{IP: lowerHalf, Mask: net.CIDRMask(int(prefix), 8*net.IPv4len)})
		err := splitRange4(lowerHalf, prefix, lo, broad, cidrs)
		if err != nil {
			return err
		}
		return splitRange4(*upperHalf, prefix, *upperHalf, hi, cidrs)
	}
}

type IPRange struct {
	First net.IP
	Last net.IP
}

func ipNetToRange(ipNet net.IPNet) (first net.IP, last net.IP) {
	fmt.Printf("len(ipNet.IP): %d\n", len(ipNet.IP))
	firstIP := make(net.IP, len(ipNet.IP))
	copy(firstIP, ipNet.IP)
	fmt.Printf("ipNet.IP: %08b\n", ipNet.IP)
	firstIP = firstIP.Mask(ipNet.Mask)
	if firstIP.To4() != nil {
		firstIP = append(ipv4Ipv6Slice, firstIP...)
	}
	fmt.Printf("firstIP: %08b\n", firstIP)

	//firstIP := ipNet.IP.Mask(ipNet.Mask)
	fmt.Printf("ipNet.IP: %s\n", ipNet.IP)
	fmt.Printf("firstIP: %s\n", firstIP)
	lastIP := make(net.IP, len(ipNet.IP))
	copy(lastIP, ipNet.IP)
	lastIPMask := make(net.IPMask, len(ipNet.Mask))
	copy(lastIPMask, ipNet.Mask)
	for i := range lastIPMask {
		lastIPMask[len(lastIPMask)-i-1] = ^lastIPMask[len(lastIPMask)-i-1]
		lastIP[net.IPv6len-i-1] = lastIP[net.IPv6len-i-1] | lastIPMask[len(lastIPMask)-i-1]
	}

	return firstIP, lastIP
}

func getPreviousIP(ip net.IP) net.IP {
	// check lower bound for each IP range?
	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	i := len(ip) - 1
	var overflow bool
	var lowerByteBound int
	if ip.To4() != nil {
		lowerByteBound = net.IPv6len - net.IPv4len
	} else {
		lowerByteBound = 0
	}
	for ; i >= lowerByteBound; i-- {
		if overflow || i == len(ip) - 1 {
			ipCopy[i]--
		}
		// Overflow condition means we need to continue
		if ip[i] == 0 && ipCopy[i] == 255 {
			overflow = true
		} else {
			overflow = false
		}
	}
	return ipCopy
}

func getNextIP(ip net.IP) net.IP {
	// check upper bound for each IP range?
	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	i := len(ip) - 1
	var overflow bool
	var lowerByteBound int
	if ip.To4() != nil {
		lowerByteBound = net.IPv6len - net.IPv4len
	} else {
		lowerByteBound = 0
	}
	for ; i >= lowerByteBound; i-- {
		if overflow || i == len(ip) - 1 {
			ipCopy[i]++
		}

		if ip[i] == 255 && ipCopy[i] == 0 {
			overflow = true
		} else {
			overflow = false
		}

	}
	return ipCopy
}

func getByteIndexOfBit(bit uint) uint {
	return net.IPv6len - (bit / 8) - 1
}

func getNthBit(ip *net.IP, bitNum uint) uint8 {
	byteNum := getByteIndexOfBit(bitNum)
	bits := (*ip)[byteNum]
	b := uint8(bits)
	return b >> (bitNum % 8) & 1
}

func flipNthBit(ip *[]byte, bitNum uint) *[]byte {
	ipCopy := make([]byte, len(*ip))
	copy(ipCopy, *ip)
	byteNum := getByteIndexOfBit(bitNum)
	ipCopy[byteNum] = ipCopy[byteNum] ^ 1<<(bitNum%8)

	return &ipCopy
}

func setNthBit(ip *[]byte, bitNum, val uint) *[]byte {
	ipCopy := make([]byte, len(*ip))
	fmt.Printf("setting bit %d to have value %d\n", bitNum, val)
	copy(ipCopy, *ip)
	fmt.Printf("ip: \t\t%08b\n", *ip)
	fmt.Printf("ipCopy: \t%08b\n", ipCopy)
	byteNum := getByteIndexOfBit(bitNum)

	if val == 0 {
		ipCopy[byteNum] = ipCopy[byteNum] & ^(1 << (bitNum%8))
	} else if val == 1 {
		ipCopy[byteNum] = ipCopy[byteNum] | (1 << (bitNum%8))
	} else {
		panic("set bit is not 0 or 1")
	}

	fmt.Printf("after set: \t%08b\n", ipCopy)
	return &ipCopy
}