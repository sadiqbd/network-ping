<?php

class network {

    function ping($ip = "127.0.0.1", $ipv = 4, $seqNumber = 0, $request_id = 0, $byte = 64, $wait = 3) {
// Making the package
        $type = pack("C", 8);
        $code = pack("C", 0);;
        $checksum = pack("n", 0);;
        $identifier = pack("n", $request_id);
        $seqNumber = pack("n", $seqNumber);
        $chars = "abcdefghijklmnopqrstuvwxys0123456789";
        $data = "";
        for($i=0; $i < $byte; $i++ )
        {
            $data .= $chars[rand(0,35)];
        }
        $package = $type . $code . $checksum . $identifier . $seqNumber . $data;
        $checksum = $this->icmpChecksum($package); // Calculate the checksum
        $package = $type . $code . $checksum . $identifier . $seqNumber . $data;
        
        // ICMP transmit socket
        $tsocket = socket_create(AF_INET, SOCK_RAW, 1);

        // ICMP receive socket
        $rsocket = socket_create(AF_INET, SOCK_RAW, 1);
        // Bind to all network interfaces
        socket_bind($rsocket, 0, 0);
        
        @socket_sendto($tsocket, $package, strlen($package), 0, $ip, 0);
        // Start timer
            $time = microtime(TRUE);
            $rset = array($rsocket);
            $tset = NULL;
            $xset = NULL;
            // Wait for incoming ICMP packet
            @socket_select($rset, $tset, $xset, $wait);
            if ($rset &&
                    @socket_recv($rsocket, $reply, 255, 0)) {
                $elapsed = 1e3 * (microtime(TRUE) - $time);
                // Socket didn't timeout; Record round-trip time
                var_dump($elapsed);

                $ip_header = $this->parse_ip_header($reply);
                $data = unpack("CType/CCode/nChecksum/nIdentifier/nSequence/A*Payload", $ip_header['payload']);
                
                if($data['Identifier'] == $request_id)
                {
                    return array('source'=>long2ip($ip_header['source_add']),'byte'=>$byte, 'ttl'=>$ip_header['ttl'],'time'=>$elapsed );
                }

            }
        socket_close($tsocket);
        socket_close($rsocket);
    }

    private function icmpChecksum($data) {
        //Source http://www.planet-source-code.com/vb/scripts/ShowCode.asp?lngWId=8&txtCodeId=1786

        if (strlen($data) % 2)
            $data .= "\x00";

        $bit = unpack('n*', $data);
        $sum = array_sum($bit);

        while ($sum >> 16)
            $sum = ($sum >> 16) + ($sum & 0xffff);

        return pack('n*', ~$sum);
    }
    
    private function parse_ip_header($data)
    {
        return unpack("Cip_ver_len/Ctos/ntot_len/nidentification/nfrag_off/Cttl/Cprotocol/nheader_checksum/Nsource_add/Ndest_add/A*payload", $data);
    }

}


$obj = new network();

var_dump($obj->ping("8.8.8.8", 4, 5, 15, 64));
