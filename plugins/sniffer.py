# coding=utf-8
# coding=utf-8
__author__ = 'root'
#!/usr/bin/env python

import socket
from struct import *
import pcapy
import sys


class Main:
    __title__ = "Sniffer"
    __description__ = ""
    __menu_entry__ = "Sniffer that allows to catch"

    def main(self):
        options = {'TCP': False, 'ICMP': False, 'UDP': False, 'OTHER': False}
        devices = pcapy.findalldevs()
        print devices
        print "[!] Dispositivos disponibles:"
        for d in devices:
            print "[o] - " + d

        dev = raw_input("[+] Introduzca el nombre del dispositivo: ")

        print "[!] Dispositivo seleccionado: " + dev

        cap = pcapy.open_live(dev, 65536, 1, 0)
        options = str(input("Introduzca las opciones:"))

        if options == 'ALL':
            options = {'TCP': True, 'ICMP': True, 'UDP': True, 'OTHER': True}
        else:

            lista_options = tuple(options.split(','))
            for opcion in lista_options:
                if opcion in options:
                    options[opcion] = True
                else:
                    print "[-] Protocolo incorrecto."

        # Empezamos a sniffar paquetes
        while (1):
            (header, packet) = cap.next()
            super.parse_packet(packet, options)


    # Parseador de la dirección mac de asignada a la ethernet
    @property
    def eth_addr(a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
        return b

    # Función de parseo del paquete
    def parse_packet(packet, options):
        # Parseo del paquete ethernet
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + super.eth_addr(packet[0:6]) + ' Source MAC : ' + super.eth_addr(
            packet[6:12]) + ' Protocol : ' + str(eth_protocol)

        # Parseamos todos los paquete tipo IP
        if eth_protocol == 8:
            #Parseamos la cabecera IP
            #Cogemos los 20 bytes desde el principio de la cabecera
            ip_header = packet[eth_length:20 + eth_length]

            #Desempaquetamos el paquete
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            # Cogemos el primer byte del iph con la versión del ihl
            version_ihl = iph[0]
            # Decodificamos la versión
            version = version_ihl >> 4
            #Calculamos el ihl completo
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            print 'Version : ' + str(version) + ' Longitud cabecera: ' + str(ihl) + ' TTL : ' + str(
                ttl) + ' Protocolo : ' + str(protocol) + ' Dirección de origen : ' + str(
                s_addr) + ' Dirección de destino : ' + str(d_addr)

            #Protocolo TCP
            if protocol == 6 and options['TCP']:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                print 'Puerto de origen : ' + str(source_port) + ' Puerto de destino : ' + str(
                    dest_port) + ' Numero de secuencia : ' + str(
                    sequence) + ' ACK : ' + str(acknowledgement) + ' Longitud cabecera : ' + str(tcph_length)

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                print 'Data: ' + data
                super.testFinder(data)

            #Paquetes de error ICMP
            elif protocol == 1 and options['ICMP']:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]

                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                data = packet[h_size:]
                print type(data)
                print 'Data : ' + data

            #Paquetes UDP
            elif protocol == 17 and options['UDP']:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                print 'Puerto de origen : ' + str(source_port) + ' Puerto de destino : ' + str(
                    dest_port) + ' Longitud : ' + str(
                    length) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                data = packet[h_size:]

                print 'Data : ' + data

            elif options['OTHER']:
                print 'Protocolo no conocido'