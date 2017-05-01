<?php
/**
 * Project Honey Pot
 *
 * @author Jamie Sage
 * @link http://www.jamiesage.co.uk/
 */

namespace ProjectHoneyPot;

use \Exception;

class HoneyPot
{
    /**
     * The API URL to query
     * @var string
     */
    private $api_url = "dnsbl.httpbl.org";

    /**
     * The Project HoneyPot access key to use
     * @var null
     */
    private $access_key = null;

    /**
     * The IP address to query
     * @var null
     */
    private $ip_address = null;

    /**
     * The response from the query
     * @var mixed
     */
    protected $response = null;

    /**
     * The type of visitors
     * @var array
     */
    protected $visitor_types = [
        0 => 'Search Engine',
        1 => 'Suspicious',
        2 => 'Harvester',
        3 => 'Suspicious & Harvester',
        4 => 'Comment Spammer',
        5 => 'Suspicious & Comment Spammer',
        6 => 'Harvester & Comment Spammer',
        7 => 'Suspicious & Harvester & Comment Spammer'
    ];

    /**
     * HoneyPot constructor
     * @param $ip_address
     * @param $access_key
     * @throws Exception
     */
    public function __construct($ip_address, $access_key)
    {
        // Validate the IP address
        if (!self::isValidAddress($ip_address)) {
            throw new Exception("Cannot query ip address '" . $ip_address . "'");
        }

        // Validate the access key
        if (!self::isValidAccessKey($access_key)) {
            throw new Exception("Please provide a valid access key");
        }

        $this->ip_address = $ip_address;
        $this->access_key = $access_key;

        // Run the checks
        $this->run();
    }

    /**
     * Verify if a string is a valid IP address which can be used to query against Project HoneyPot
     * @param $ip_address
     * @return bool
     */
    public static function isValidAddress($ip_address)
    {
        return filter_var($ip_address, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Check if a string is in a valid format to be a Project HoneyPot access key
     * @param $access_key
     * @return bool
     */
    public static function isValidAccessKey($access_key)
    {
        return (bool)preg_match('/^[a-z]{12}$/', $access_key);
    }

    /**
     * Get the last activity of the response
     * @return bool|int
     */
    public function getLastActivity()
    {
        if ($this->response !== null) {
            return intval($this->response[1]);
        }
        return false;
    }

    /**
     * Get the threat score of the response
     * @return bool|int
     */
    public function getThreatScore()
    {
        if ($this->response !== null) {
            return intval($this->response[2]);
        }
        return false;
    }

    /**
     * Get the visitor type of the response
     * @return bool|string
     */
    public function getVisitorType()
    {
        if ($this->response !== null) {
            $type = intval($this->response[3]);

            // If we don't have a visitor type stored, it is a reserved type
            if ($type >= sizeof($this->visitor_types)) {
                return 'Reserved visitor type';
            }

            return $this->visitor_types[$type];
        }
        return false;
    }

    /**
     * Get an array comprising of all of the responses information
     * @return array|bool
     */
    public function all()
    {
        if ($this->response !== null) {
            return [
                'last_activity' => $this->getLastActivity(),
                'threat_score' => $this->getThreatScore(),
                'visitor_type' => $this->getVisitorType()
            ];
        }
        return false;
    }

    /**
     * Run a query against the IP Address
     * @throws Exception
     * @return bool
     */
    private function run()
    {
        // Reverse the order of the octets
        $ip_reverse = implode(array_reverse(explode(".", $this->ip_address)), ".");

        // Get the response
        $hostname = $this->access_key . "." . $ip_reverse . "." . $this->api_url;
        $query = gethostbyname($hostname);

        // Explode the response
        $response = explode(".", $query);

        if ($response === null || $query === $hostname) {
            $this->response = null;
            return false;
        }

        // Validate the response
        if (sizeof($response) !== 4 || (sizeof($response) === 4 && $response[0] !== "127")) {
            throw new Exception(
                "Unable to query '" . $this->ip_address . "'. Is your query formatted correctly?"
            );
        }

        // Update the response
        $this->response = $response;
        return true;
    }
}
