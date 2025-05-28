Usernames and passwords:
    Username: studentuser
    Password: student
Project Wiki: 
    Username: admin@local.com
    Password: studentuser

SSH:
No keys, any computer with VPN access can SSH into the VMs.

Access methods:
    VMs: SSH, Proxmox Console.
    
    IMPORTANT: Local roject Wiki located on Visuals VM on port 3000. (http://10.0.0.86:3000)

    Docker Swarm Stacks:
        Elk:
            Kibana: https://10.0.0.81:5601   #Network packet inspection dashboard
        Monitor:
            Grafana: https://10.0.0.81:3000   #Network packet flow dashboard
            Prometheus: http://10.0.0.81:9090   #Network pack database
            Cadvisor: http://10.0.0.8[1-3]:8080   #Container monitoring website
        Cowrie:
            Cowrie: SSH 10.0.0.82 -p2222   #Honeypot virtual environment access
        Dionaea:
            Dionaea: http://10.0.0.83/index.php   #Placeholder page for dionaea honeypot

IP Addresses:
    Main: 10.0.0.81
    Node1: 10.0.0.82
    Node2: 10.0.0.83
    Visuals (Linux GUI env): 10.0.0.86
    EvilEve: 10.0.0.87
