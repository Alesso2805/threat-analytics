package com.threat.analytics.sniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class SnifferApplication {

    private static final Logger log = LoggerFactory.getLogger(SnifferApplication.class);
    
    private static final String BPF_FILTER = "tcp port 80 or tcp port 443";
    private static final int SNAPLEN = 65536; 
    private static final int TIMEOUT = 10;  

    // Estado para Detección de DDoS
    private static final ConcurrentHashMap<String, AtomicInteger> ipRequestCount = new ConcurrentHashMap<>();
    private static final int DDOS_THRESHOLD = 50; // umbral de paquetes por segundo

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        System.out.println("==================================================");
        System.out.println("🔥 Iniciando Agente de Captura de Red IA (Core Java) 🔥");
        System.out.println("==================================================");

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            System.setProperty("jna.library.path", "C:\\Windows\\System32\\Npcap");
            System.out.println("✔️ Entorno Windows detectado. Ruta JNA configurada automáticamente.");
        }

        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        
        if (allDevs == null || allDevs.isEmpty()) {
            System.err.println("❌ ERROR: No se detectó ninguna interfaz de red. Npcap no está corriendo o falta permisos de Admin.");
            return;
        }

        System.out.println("✔️ Interfaces Disponibles detectadas por Npcap:");
        for (int i = 0; i < allDevs.size(); i++) {
            System.out.printf("[%d] Nombre: %s | Detalles: %s%n", i, allDevs.get(i).getName(), allDevs.get(i).getDescription());
        }

        System.out.print("\n👉 Escribe el NÚMERO de la interfaz que deseas escuchar (ej: 6) o [7] para loopback y presiona Enter: ");
        int adapterIndex = 0;
        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
            adapterIndex = Integer.parseInt(scanner.nextLine().trim());
        } catch (Exception e) {
            System.out.println("Entrada inválida. Usando interfaz [0] por defecto.");
        }

        PcapNetworkInterface nif = allDevs.get(adapterIndex); 
        System.out.println("\n📡 Conectando (Sniffing) a la interfaz: " + nif.getDescription());

        final PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT);

        try {
            handle.setFilter(BPF_FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);
            System.out.println("✔️ Filtro BPF (C/C++) Inyectado en Npcap: " + BPF_FILTER);
        } catch (Exception e) {
            log.warn("Filtro BPF no pudo ser aplicado (" + BPF_FILTER + "). Capturando todo el tráfico (mucho ruido).");
        }

        PacketListener listener = rawPacket -> {
            Thread.ofVirtual().start(() -> processPacket(rawPacket));
        };

        // Hilo paralelo (Virtual Thread) para limpiar el contador cada segundo
        Thread.ofVirtual().start(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    ipRequestCount.clear(); // reiniciar conteo (ventana de 1 seg)
                } catch (InterruptedException e) {
                    break;
                }
            }
        });

        System.out.println("\n🌐 Escuchando paquetes en tiempo real... (Presiona Ctrl+C para detener)");
        
        try {
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            System.out.println("\nCerrando sniffer adecuadamente...");
        } finally {
            handle.close();
            System.out.println("Sesión Cerrada.");
        }
    }

    private static void processPacket(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            String sourceIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String destIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcp = packet.get(TcpPacket.class);
                int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                int dstPort = tcp.getHeader().getDstPort().valueAsInt();

                // Contar paquetes por IP en el último segundo
                int count = ipRequestCount.computeIfAbsent(sourceIp, k -> new AtomicInteger(0)).incrementAndGet();

                if (count > DDOS_THRESHOLD) {
                    if (count == DDOS_THRESHOLD + 1) { 
                        // Solo imprimimos la alerta fuerte una vez por segundo para no trabar la terminal
                        System.err.printf("🚨 [ALERTA DE SEGURIDAD] ¡Posible ataque DDoS / SYN Flood detectado! La IP %s envió más de %d paquetes en 1 segundo.%n", sourceIp, DDOS_THRESHOLD);
                    }
                } else {
                    // Imprimir tráfico normal
                    System.out.printf("[%s] -> 🔴 Conexión TCP Detectada: %s:%d -> %s:%d%n", 
                        Thread.currentThread().getName(), sourceIp, srcPort, destIp, dstPort);
                }
            }
        }
    }
}