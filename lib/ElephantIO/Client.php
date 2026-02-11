<?php

namespace ElephantIO;

require_once(__DIR__.'/Payload.php');
require_once(__DIR__.'/Frame.php');

/**
 * ElephantIOClient - Socket.io 4.x compatible PHP client
 *
 * Updated to support Socket.io 4.x / Engine.IO 4 protocol
 * Original author: Ludovic Barreca <ludovic@balloonup.com>
 * Socket.io 4.x update: Handbid Inc.
 */
class Client {
    // Legacy type constants (kept for backward compatibility with Frame.php)
    const TYPE_DISCONNECT   = 0;
    const TYPE_CONNECT      = 1;
    const TYPE_HEARTBEAT    = 2;
    const TYPE_MESSAGE      = 3;
    const TYPE_JSON_MESSAGE = 4;
    const TYPE_EVENT        = 5;
    const TYPE_ACK          = 6;
    const TYPE_ERROR        = 7;
    const TYPE_NOOP         = 8;

    // Engine.IO 4 packet types
    const EIO_OPEN          = 0;
    const EIO_CLOSE         = 1;
    const EIO_PING          = 2;
    const EIO_PONG          = 3;
    const EIO_MESSAGE       = 4;
    const EIO_UPGRADE       = 5;
    const EIO_NOOP          = 6;

    // Socket.IO 4 packet types (within EIO_MESSAGE)
    const SIO_CONNECT       = 0;
    const SIO_DISCONNECT    = 1;
    const SIO_EVENT         = 2;
    const SIO_ACK           = 3;
    const SIO_CONNECT_ERROR = 4;
    const SIO_BINARY_EVENT  = 5;
    const SIO_BINARY_ACK    = 6;

    public $origin = '*';
    public $cookie;
    public $sendCookie = false;

    private $baseUrl;
    private $serverHost;
    private $serverPort = 80;
    private $serverPath;
    private $session;
    private $fd;
    private $buffer;
    private $lastId = 0;
    private $read;
    private $checkSslPeer = true;
    private $debug;
    private $handshakeTimeout = null;
    private $endpoints = array();
    private $eioVersion = 4;
    private $isSecure = false;
    private $heartbeatStamp;

    /**
     * @param string $socketIOUrl Base URL (e.g., 'http://localhost:3000')
     * @param string $socketIOPath Path prefix (default: 'socket.io')
     * @param int $protocol Protocol version (ignored, always uses EIO=4)
     * @param bool $read Whether to read responses
     * @param bool $checkSslPeer Whether to verify SSL certificates
     * @param bool $debug Enable debug output
     */
    public function __construct($socketIOUrl, $socketIOPath = 'socket.io', $protocol = 1, $read = true, $checkSslPeer = true, $debug = false) {
        // Parse the base URL
        $parsed = parse_url($socketIOUrl);

        $this->isSecure = isset($parsed['scheme']) && $parsed['scheme'] === 'https';
        $this->serverHost = $parsed['host'];
        $this->serverPort = isset($parsed['port']) ? $parsed['port'] : ($this->isSecure ? 443 : 80);
        $this->serverPath = '/' . trim($socketIOPath, '/');
        $this->baseUrl = $socketIOUrl . '/' . trim($socketIOPath, '/');

        $this->read = $read;
        $this->debug = $debug;
        $this->checkSslPeer = $checkSslPeer;
    }

    /**
     * Initialize a new connection
     *
     * @param boolean $keepalive
     * @return Client
     */
    public function init($keepalive = false) {
        $this->handshake();
        $this->connect();

        if ($keepalive) {
            $this->keepAlive();
        } else {
            return $this;
        }
    }

    /**
     * Keep the connection alive and dispatch events
     *
     * @access public
     */
    public function keepAlive() {
        while(true) {
            if ($this->session['pingInterval'] > 0) {
                $pingIntervalSec = $this->session['pingInterval'] / 1000;
                if ($this->heartbeatStamp + $pingIntervalSec - 5 < time()) {
                    $this->sendPing();
                    $this->heartbeatStamp = time();
                }
            }

            $r = array($this->fd);
            $w = $e = null;

            if (stream_select($r, $w, $e, 5) == 0) continue;

            $this->read();
        }
    }

    /**
     * Send a ping packet
     */
    private function sendPing() {
        $this->write($this->encode((string)self::EIO_PING));
        $this->stdout('debug', 'Sent ping');
    }

    /**
     * Read the buffer and return the oldest event in stack
     *
     * @access public
     * @return string
     */
    public function read($timeout = 2) {
        // Wait for data to be available using stream_select
        $read = array($this->fd);
        $write = $except = null;
        $ready = stream_select($read, $write, $except, $timeout);

        if ($ready === false || $ready === 0) {
            $this->stdout('debug', 'No data available (timeout=' . $timeout . 's)');
            return '';
        }

        // Read WebSocket frame header
        $firstByte = fread($this->fd, 1);
        if ($firstByte === false || strlen($firstByte) === 0) {
            return '';
        }

        $secondByte = fread($this->fd, 1);
        $payload_len = ord($secondByte) & 0x7F;

        switch ($payload_len) {
            case 126:
                $payload_len = unpack("n", fread($this->fd, 2));
                $payload_len = $payload_len[1];
                break;
            case 127:
                $this->stdout('error', "64bit payload length not yet implemented");
                return '';
        }

        $payload = '';
        while (strlen($payload) < $payload_len) {
            $chunk = fread($this->fd, $payload_len - strlen($payload));
            if ($chunk === false) break;
            $payload .= $chunk;
        }

        $this->stdout('debug', 'Received: ' . $payload);

        return $payload;
    }

    /**
     * Join into socket.io namespace
     *
     * @param string $endpoint
     * @return Client
     */
    public function of($endpoint = null) {
        if ($endpoint && !in_array($endpoint, $this->endpoints)) {
            // Socket.io 4.x namespace connection: 40/namespace,{}
            $namespacePacket = self::EIO_MESSAGE . '' . self::SIO_CONNECT . $endpoint . ',{}';
            $this->write($this->encode($namespacePacket));
            $this->endpoints[] = $endpoint;
            $this->stdout('debug', 'Joining namespace: ' . $endpoint . ' with packet: ' . $namespacePacket);

            // Read namespace connection acknowledgment
            if ($this->read) {
                $response = $this->read();
                $this->stdout('debug', 'Namespace response: ' . $response);
            }
        }
        return $this;
    }

    /**
     * Leave a namespace
     *
     * @return Client
     */
    public function leaveEndpoint($endpoint) {
        if ($endpoint && in_array($endpoint, $this->endpoints)) {
            // Socket.io 4.x namespace disconnect: 41/namespace,
            $disconnectPacket = self::EIO_MESSAGE . '' . self::SIO_DISCONNECT . $endpoint . ',';
            $this->write($this->encode($disconnectPacket));
            unset($this->endpoints[array_search($endpoint, $this->endpoints)]);
        }
        return $this;
    }

    /**
     * @return Frame
     */
    public function createFrame($type = null, $endpoint = null) {
        return new Frame($this, $type, $endpoint);
    }

    /**
     * @param Frame $frame
     */
    public function sendFrame(Frame $frame) {
        $this->send(
            $frame->getType(),
            $frame->getId(),
            $frame->getEndPoint(),
            $frame->getData()
        );
    }

    /**
     * Send message to the websocket (legacy compatibility wrapper)
     *
     * @access public
     * @param int $type
     * @param int $id
     * @param string $endpoint
     * @param string $message
     * @return Client
     */
    public function send($type, $id = null, $endpoint = null, $message = null) {
        // Convert legacy type to Socket.io 4.x format
        $this->of($endpoint);

        // For EVENT type, message is already JSON with 'name' and 'args'
        if ($type == self::TYPE_EVENT && $message) {
            $decoded = json_decode($message, true);
            if ($decoded && isset($decoded['name'])) {
                $eventName = $decoded['name'];
                $args = isset($decoded['args']) ? $decoded['args'] : [];

                // Build Socket.io 4.x event packet: 42/namespace,["event",arg1,arg2,...]
                $eventData = array_merge([$eventName], $args);
                $packet = self::EIO_MESSAGE . '' . self::SIO_EVENT;
                if ($endpoint) {
                    $packet .= $endpoint . ',';
                }
                $packet .= json_encode($eventData);

                $this->write($this->encode($packet));
                $this->stdout('debug', 'Sent event: ' . $packet);
            }
        }

        return $this;
    }

    /**
     * Emit an event
     *
     * @param string $event
     * @param array $args
     * @param string $endpoint
     * @param callable $callback - ignored for the time being
     */
    public function emit($event, $args, $endpoint = null, $callback = null) {
        $this->of($endpoint);

        // Build Socket.io 4.x event packet: 42["event",arg1,arg2,...] or 42/namespace,["event",...]
        $eventData = array_merge([$event], (array)$args);
        $packet = self::EIO_MESSAGE . '' . self::SIO_EVENT;
        if ($endpoint) {
            $packet .= $endpoint . ',';
        }
        $packet .= json_encode($eventData);

        $this->write($this->encode($packet));
        $this->stdout('debug', 'Emitted: ' . $packet);
    }

    /**
     * Emit an event and wait for server acknowledgment
     *
     * This provides guaranteed delivery - the method only returns successfully
     * when the server has confirmed receipt of the event.
     *
     * @param string $event Event name
     * @param array $args Event arguments
     * @param string $endpoint Namespace (e.g., '/server')
     * @param int $timeout Timeout in seconds to wait for ack
     * @return bool True if acknowledged
     * @throws \RuntimeException If ack not received within timeout
     */
    public function emitWithAck($event, $args, $endpoint = null, $timeout = 5) {
        $this->of($endpoint);

        // Generate unique ack ID
        $ackId = ++$this->lastId;

        // Build Socket.io 4.x event packet WITH ack ID:
        // Format: 42/namespace,<ackId>["event",arg1,arg2,...]
        // The ack ID comes BEFORE the JSON array
        $eventData = array_merge([$event], (array)$args);
        $packet = self::EIO_MESSAGE . '' . self::SIO_EVENT;
        if ($endpoint) {
            $packet .= $endpoint . ',';
        }
        $packet .= $ackId . json_encode($eventData);

        $this->write($this->encode($packet));
        $this->stdout('debug', 'Emitted with ack (id=' . $ackId . '): ' . $packet);

        // Wait for ack response: 43/namespace,<ackId>[data] or 43<ackId>[data]
        $startTime = time();
        $attempts = 0;
        while ((time() - $startTime) < $timeout) {
            $attempts++;
            $response = $this->read(1); // 1 second read timeout per attempt

            if (empty($response)) {
                continue; // No data yet, keep waiting
            }

            $this->stdout('debug', 'Received response: ' . $response);

            // Parse ack response
            // Format: 43/namespace,<ackId>[...] or 43<ackId>[...]
            // Engine.IO MESSAGE (4) + Socket.IO ACK (3) = "43"
            if (strpos($response, '43') === 0) {
                // Extract ack ID from response
                $ackPart = substr($response, 2); // Remove "43"

                // Handle namespace prefix if present
                if ($endpoint && strpos($ackPart, $endpoint . ',') === 0) {
                    $ackPart = substr($ackPart, strlen($endpoint) + 1);
                }

                // Extract numeric ack ID (everything before '[')
                $bracketPos = strpos($ackPart, '[');
                if ($bracketPos !== false) {
                    $responseAckId = (int)substr($ackPart, 0, $bracketPos);
                } else {
                    $responseAckId = (int)$ackPart;
                }

                if ($responseAckId === $ackId) {
                    $this->stdout('debug', 'Ack received for id=' . $ackId);
                    if (class_exists('\Yii', false)) {
                        \Yii::info("[SOCKET-ACK-OK] event={$event} ackId={$ackId} attempts={$attempts}", 'node-events');
                    }
                    return true;
                } else {
                    $this->stdout('debug', 'Ack ID mismatch: expected=' . $ackId . ', got=' . $responseAckId);
                    if (class_exists('\Yii', false)) {
                        \Yii::warning("[SOCKET-ACK-MISMATCH] event={$event} expected={$ackId} got={$responseAckId}", 'node-events');
                    }
                }
            }

            // Handle ping during wait (keep connection alive)
            if ($response === '2') {
                $this->write($this->encode('3')); // Send pong
                $this->stdout('debug', 'Responded to ping while waiting for ack');
            }
        }

        // Log timeout
        if (class_exists('\Yii', false)) {
            \Yii::error("[SOCKET-ACK-TIMEOUT] event={$event} ackId={$ackId} timeout={$timeout}s attempts={$attempts}", 'node-events');
        }

        throw new \RuntimeException(
            'Socket.io acknowledgment not received within ' . $timeout . ' seconds for event: ' . $event
        );
    }

    /**
     * Check if the WebSocket connection is still alive
     *
     * @return bool
     */
    public function isConnected() {
        return $this->fd && !feof($this->fd);
    }

    /**
     * Reconnect by closing the current connection and re-initializing.
     * Resets internal state (namespace subscriptions, ack IDs, session)
     * so the new connection starts clean.
     */
    public function reconnect() {
        $this->close();
        $this->endpoints = [];
        $this->lastId = 0;
        $this->session = null;
        $this->handshake();
        $this->connect();
    }

    /**
     * Close the socket
     *
     * @return boolean
     */
    public function close() {
        if ($this->fd) {
            // Send Engine.IO close packet (ignore errors if connection already closed)
            @$this->write($this->encode((string)self::EIO_CLOSE), false);
            @fclose($this->fd);
            $this->fd = null;
            return true;
        }
        return false;
    }

    protected function write($data, $sleep = false) {
        if (!$this->fd) {
            throw new \RuntimeException('The connection is lost');
        }
        fwrite($this->fd, $data);
        // Note: 100ms delay removed - Socket.io 4.x has proper WebSocket framing
        // If race conditions occur, set $sleep = true or add delay before close()
        if ($sleep) {
            usleep(100 * 1000);
        }
        return $this;
    }

    /**
     * @return resource
     * @throws \RuntimeException
     */
    private function getSocket() {
        if (!$this->fd) {
            throw new \RuntimeException('The connection is lost');
        }
        return $this->fd;
    }

    /**
     * Encode message as WebSocket frame
     *
     * @param string $message
     * @param int $opCode
     * @param bool $mask
     * @return string
     */
    private function encode($message, $opCode = Payload::OPCODE_TEXT, $mask = true) {
        $payload = new Payload();
        return $payload
                ->setOpcode($opCode)
                ->setMask($mask)
                ->setPayload($message)
                ->encodePayload();
    }

    /**
     * Send ANSI formatted message to stdout.
     *
     * @access private
     * @param string $type
     * @param string $message
     */
    private function stdout($type, $message) {
        if (!defined('STDOUT') || !$this->debug) {
            return false;
        }

        $typeMap = array(
            'debug'   => array(36, '- debug -'),
            'info'    => array(37, '- info  -'),
            'error'   => array(31, '- error -'),
            'ok'      => array(32, '- ok    -'),
        );

        if (!array_key_exists($type, $typeMap)) {
            throw new \InvalidArgumentException('ElephantIOClient::stdout $type parameter must be debug, info, error or ok. Got '.$type);
        }

        fwrite(STDOUT, "\033[".$typeMap[$type][0]."m".$typeMap[$type][1]."\033[37m  ".$message."\r\n");
    }

    private function generateKey($length = 16) {
        $c = 0;
        $tmp = '';

        while($c++ * 16 < $length) {
            $tmp .= md5(mt_rand(), true);
        }

        return base64_encode(substr($tmp, 0, $length));
    }

    /**
     * Set Handshake timeout in milliseconds
     *
     * @param int $delay
     */
    public function setHandshakeTimeout($delay) {
        $this->handshakeTimeout = $delay;
    }

    /**
     * @return string
     */
    private function getOriginHeader() {
        if ($this->origin) {
            if (strpos($this->origin, 'http://') === false && strpos($this->origin, 'https://') === false) {
                return sprintf("Origin: http://%s\r\n", $this->origin);
            } else {
                return sprintf("Origin: %s\r\n", $this->origin);
            }
        }
        return "Origin: *\r\n";
    }

    /**
     * Handshake with socket.io 4.x server
     *
     * @access private
     * @return bool
     */
    private function handshake() {
        // Socket.io 4.x handshake URL: /socket.io/?EIO=4&transport=polling
        $handshakeUrl = $this->baseUrl . '/?EIO=' . $this->eioVersion . '&transport=polling';

        $this->stdout('debug', 'Handshake URL: ' . $handshakeUrl);

        $ch = curl_init($handshakeUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if (!$this->checkSslPeer) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        }

        if (!is_null($this->handshakeTimeout)) {
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $this->handshakeTimeout);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $this->handshakeTimeout);
        }

        $headers = array();
        if ($this->origin) {
            $headers[] = 'Origin: ' . ($this->origin === '*' ? '*' : $this->origin);
        }
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        if ($this->sendCookie && $this->cookie) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->cookie);
        }

        $res = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($res === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new \Exception('Handshake cURL error: ' . $error);
        }

        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \Exception('Handshake failed with HTTP ' . $httpCode . ': ' . $res);
        }

        $this->stdout('debug', 'Handshake response: ' . $res);

        // Socket.io 4.x response format: 0{"sid":"xxx","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000}
        // The leading '0' is the Engine.IO OPEN packet type
        if (strlen($res) > 0 && $res[0] === '0') {
            $jsonData = substr($res, 1);
            $data = json_decode($jsonData, true);

            if (!$data || !isset($data['sid'])) {
                throw new \Exception('Invalid handshake response: ' . $res);
            }

            $this->session = array(
                'sid' => $data['sid'],
                'upgrades' => isset($data['upgrades']) ? $data['upgrades'] : array(),
                'pingInterval' => isset($data['pingInterval']) ? $data['pingInterval'] : 25000,
                'pingTimeout' => isset($data['pingTimeout']) ? $data['pingTimeout'] : 20000,
                'maxPayload' => isset($data['maxPayload']) ? $data['maxPayload'] : 1000000,
            );

            $this->stdout('info', 'Handshake successful, sid: ' . $this->session['sid']);

            if (!in_array('websocket', $this->session['upgrades'])) {
                throw new \Exception('Server does not support websocket upgrade');
            }

            return true;
        }

        throw new \Exception('Unexpected handshake response format: ' . $res);
    }

    /**
     * Connects using websocket protocol (Socket.io 4.x)
     *
     * @access private
     * @return bool
     */
    private function connect() {
        $host = $this->isSecure ? 'ssl://' . $this->serverHost : $this->serverHost;

        $this->fd = fsockopen($host, $this->serverPort, $errno, $errstr, 10);

        if (!$this->fd) {
            throw new \Exception('fsockopen error: ' . $errstr . ' (' . $errno . ')');
        }

        // Set read/write timeout for the socket (5 seconds)
        stream_set_timeout($this->fd, 5);

        $key = $this->generateKey();

        // Socket.io 4.x WebSocket upgrade path: /socket.io/?EIO=4&transport=websocket&sid=xxx
        $path = $this->serverPath . '/?EIO=' . $this->eioVersion . '&transport=websocket&sid=' . $this->session['sid'];

        $out  = "GET " . $path . " HTTP/1.1\r\n";
        $out .= "Host: " . $this->serverHost . "\r\n";
        $out .= "Upgrade: websocket\r\n";
        $out .= "Connection: Upgrade\r\n";
        $out .= "Sec-WebSocket-Key: " . $key . "\r\n";
        $out .= "Sec-WebSocket-Version: 13\r\n";
        if ($this->sendCookie && $this->cookie) {
            $out .= "Cookie: " . $this->cookie . "\r\n";
        }
        $out .= $this->getOriginHeader();
        $out .= "\r\n";

        $this->stdout('debug', 'WebSocket upgrade request: ' . $path);

        fwrite($this->fd, $out);

        $res = fgets($this->fd);

        if ($res === false) {
            throw new \Exception('Socket.io did not respond to WebSocket upgrade');
        }

        if (strpos($res, '101') === false) {
            throw new \Exception('WebSocket upgrade failed: ' . trim($res));
        }

        // Read remaining headers
        while(true) {
            $res = trim(fgets($this->fd));
            if ($res === '') break;
        }

        $this->stdout('info', 'WebSocket connected');

        // Engine.IO 4 upgrade handshake:
        // 1. Send "2probe" (ping with probe payload)
        $this->stdout('debug', 'Sending probe ping...');
        $this->write($this->encode(self::EIO_PING . 'probe'), false);

        // 2. Wait for "3probe" (pong with probe payload)
        if ($this->read) {
            $probeResponse = $this->read();
            $this->stdout('debug', 'Probe response: ' . $probeResponse);
            if ($probeResponse !== '3probe') {
                $this->stdout('error', 'Expected 3probe, got: ' . $probeResponse);
            }
        }

        // 3. Send "5" (upgrade packet)
        $this->stdout('debug', 'Sending upgrade packet...');
        $this->write($this->encode((string)self::EIO_UPGRADE), false);

        // 4. Now send Socket.IO connect packet for default namespace
        // Format: 40 (EIO message + SIO connect)
        $connectPacket = self::EIO_MESSAGE . '' . self::SIO_CONNECT;
        $this->write($this->encode($connectPacket));

        // Read connection acknowledgment
        if ($this->read) {
            $response = $this->read();
            $this->stdout('debug', 'Connect response: ' . $response);

            // Expected: 40{"sid":"..."} for successful connection
            if (strpos($response, '40') !== 0) {
                $this->stdout('error', 'Unexpected connect response: ' . $response);
            }
        }

        $this->heartbeatStamp = time();

        return true;
    }
}
