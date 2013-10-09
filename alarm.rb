#!/usr/bin/ruby
require 'packetfu'

pkt_array = PacketFu::Capture.new(:start => true, :iface => 'en1', :promisc => true, :filter => 'tcp')
pkt_array.stream.each do |p|
pkt = PacketFu:: Packet.parse p
data =pkt.payload()

 # Nmap Scan

  if  pkt.tcp_flags.urg == 1 &&  pkt.tcp_flags.psh == 1 && pkt.tcp_flags.fin == 1 
      protocol = "tcp"
      incident_number = 1
      attack = "XmasScan"
      puts "#{incident_number}. ALERT: #{attack} is detected from #{pkt.ip_saddr} (#{protocol})!"
    
    elsif pkt.tcp_flags.urg == 0 && pkt.tcp_flags.ack == 0 && pkt.tcp_flags.psh == 0 && pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.fin == 0
      protocol = "tcp"
      incident_number = 2
      attack = "NullScan"
      puts "#{incident_number}. ALERT: #{attack} is detected from #{pkt.ip_saddr} (#{protocol})!"   
      
  end 
  if  matches = pkt.payload.scan(/nmap/i).empty? 
    else
      protocol = "tcp"
      incident_number = 3
      attack = "NmapScan"
      puts "#{incident_number}. ALERT: #{attack} is detected from #{pkt.ip_saddr} (#{protocol})!"    

  end

# Password Detection
  
    if matches = data.scan(/pass/ix).empty?
    else
      incident_number = 4
      attack = "Password"
      protocol = "HTTP"
      puts "#{incident_number}. ALERT: #{attack} leaked  from #{pkt.ip_saddr} (#{protocol})!"    
    end

# Creditcard detection

    if  data.scan(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/ix).empty?
        if data.scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ix).empty? 
            if  data.scan(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ix).empty? 
                if data.scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ix).empty?
                  else
                    incident_number = 5
                    attack = "Creditcard"
                    protocol = "HTTP"
                    puts "#{incident_number}. ALERT: #{attack} leaked  from #{pkt.ip_saddr} (#{protocol})!"   
                end

              else
                incident_number = 5
                attack = "Creditcard"
                protocol = "HTTP"
                puts "#{incident_number}. ALERT: #{attack} leaked  from #{pkt.ip_saddr} (#{protocol})!" 
            end
          else
            incident_number = 5
            attack = "Creditcard"
            protocol = "HTTP"
            puts "#{incident_number}. ALERT: #{attack} leaked  from #{pkt.ip_saddr} (#{protocol})!" 
        end
      else
          incident_number = 5
          attack = "Creditcard"
          protocol = "HTTP"
          puts "#{incident_number}. ALERT: #{attack} leaked  from #{pkt.ip_saddr} (#{protocol})!" 
  
    end

# Cross site scripting

  if matches = data.scan(/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix).empty?
  else
    if  matches = data.scan(/script/).empty?
      else
        incident_number = 6
        attack = "Cross site scripting"
        protocol = "HTTP"
        puts "#{incident_number}. ALERT: #{attack} is detected from #{pkt.ip_saddr} (#{protocol})!"    

    end
  end

end


   

