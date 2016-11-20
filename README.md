Watch: https://www.youtube.com/watch?v=XOcbwChidB0    

In this video I explain the client and server running a simple layer 2 datalink protocol (header, packet count, and CRC) that I wrote in C, and then demo them using a remote server hosted by Google's Cloud Platform. In the demo, the client alternates between sending (psuedo) randomly corrupt and correct packets, while the server will attempt to verify the packet with a CRC check and either request a retransmission or return an ACK message. A .wav file is sent to the server and back.
