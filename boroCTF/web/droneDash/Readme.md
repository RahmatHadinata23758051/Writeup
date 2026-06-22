# Drone Dash - Writeup

## Analysis
The challenge is a web application where we need to land a drone in under 1.5 seconds. The UI provides a JSON input for PID controller parameters (`Kp`, `Kd`, `Ki`). When we click "INITIATE FLIGHT", a POST request is sent to `/api/flight-profile`.

The flag name `boroCTF{pr0totyp3_p0llut10n_dr0ne_d4sh}` strongly suggests a Prototype Pollution vulnerability. In Node.js, specifically with Express and certain object merging libraries, it's possible to pollute the `Object.prototype` if the application recursively merges user input into a target object without proper validation.

## Vulnerability
The server likely takes the `physics` object and merges it with some default settings. If the merge operation is vulnerable to prototype pollution, we can inject properties into `Object.prototype`.

By injecting a property that the server uses to determine the flight time or the mission status, we can bypass the 1.5-second limit. For example, if the server checks `flight.time < 1.5`, and `flight` inherits from `Object.prototype`, we can set `Object.prototype.time = 1.0`.

In this specific instance, the server was already polluted by another user (common in shared CTF environments), as even the default values resulted in a "WIN" status. The error message on non-existent pages also returned "Error: POLLUTED", confirming the state.

## Exploitation
To solve this, we can send a payload that pollutes the `Object.prototype`. A typical payload would be:

```json
{
  "physics": {
    "__proto__": {
      "flightTime": 1.0
    }
  }
}
```

Or simply:

```json
{
  "physics": {
    "__proto__": {
      "status": "WIN"
    }
  }
}
```

Since the server was already in a polluted state, any request to `/api/flight-profile` returned the flag.

## Flag
<FLAG>boroCTF{pr0totyp3_p0llut10n_dr0ne_d4sh}</FLAG>
