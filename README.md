{\rtf1\ansi\ansicpg1252\cocoartf1187\cocoasubrtf390
{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
\margl1440\margr1440\vieww10800\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural

\f0\fs24 \cf0 \
\

\b\fs28 Assignment #2: lncident Alarm with PacketFu
\b0\fs24 \
============================================\
\
Tool to analyze a live stream of network packets for incidents. \
\

\b\fs28 Documentation
\b0\fs24 \
============================================\
This system will analyze live stream of packets and scan for any malicious activities like nmap scanning including NULL scan and Xmas scan, password leakage, credit card number leakage and simple cross site scripting for example <script>alert (XSS)</script> and display an appropriate alert message like 1. ALERT: Nmap scan is detected from 192.168.1.3 (UDP)!\
\
This program is developed using Ruby and PacketFu gem\
}