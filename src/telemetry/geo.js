'use strict';

// Where a sign-in came from, and whether getting between two of them was physically possible.
//
// Red has no GeoIP database - that is a licensed binary this project deliberately doesn't
// carry - so location comes from the IANA time zone the browser reports, which is named after
// a real city and is a good deal more honest than guessing from an address. `locate` is the
// single seam: give it a real GeoIP lookup and everything above it keeps working unchanged.
//
// The schema already has latitude, longitude and country_code on user_sessions and
// auth_events, so a resolved location is stored there rather than in something invented.

const EARTH_RADIUS_KM = 6371;

// A commercial jet cruises at about 900 km/h. Sustaining that average between two sign-ins,
// airports and all, is not possible - which is the point.
const MAX_SPEED_KMH = 900;
// Below this, two cities are close enough that a fast train, a time-zone border or a slightly
// wrong coordinate could explain it. Only real distance counts.
const MIN_DISTANCE_KM = 400;

// Approximate coordinates for the IANA zones people actually use, taken from the city each
// zone is named after. Country code is the zone's own, used for new_geolocation_login_flag.
const ZONES = {
  // Europe
  'Europe/London': [51.51, -0.13, 'GB'], 'Europe/Dublin': [53.35, -6.26, 'IE'],
  'Europe/Lisbon': [38.72, -9.14, 'PT'], 'Europe/Madrid': [40.42, -3.70, 'ES'],
  'Europe/Paris': [48.86, 2.35, 'FR'], 'Europe/Brussels': [50.85, 4.35, 'BE'],
  'Europe/Amsterdam': [52.37, 4.90, 'NL'], 'Europe/Berlin': [52.52, 13.41, 'DE'],
  'Europe/Zurich': [47.38, 8.54, 'CH'], 'Europe/Vienna': [48.21, 16.37, 'AT'],
  'Europe/Rome': [41.90, 12.50, 'IT'], 'Europe/Prague': [50.08, 14.44, 'CZ'],
  'Europe/Warsaw': [52.23, 21.01, 'PL'], 'Europe/Budapest': [47.50, 19.04, 'HU'],
  'Europe/Stockholm': [59.33, 18.07, 'SE'], 'Europe/Oslo': [59.91, 10.75, 'NO'],
  'Europe/Copenhagen': [55.68, 12.57, 'DK'], 'Europe/Helsinki': [60.17, 24.94, 'FI'],
  'Europe/Athens': [37.98, 23.73, 'GR'], 'Europe/Bucharest': [44.43, 26.10, 'RO'],
  'Europe/Sofia': [42.70, 23.32, 'BG'], 'Europe/Kyiv': [50.45, 30.52, 'UA'],
  'Europe/Kiev': [50.45, 30.52, 'UA'], 'Europe/Moscow': [55.76, 37.62, 'RU'],
  'Europe/Istanbul': [41.01, 28.98, 'TR'], 'Europe/Belgrade': [44.79, 20.45, 'RS'],
  'Europe/Zagreb': [45.81, 15.98, 'HR'], 'Europe/Bratislava': [48.15, 17.11, 'SK'],
  'Europe/Ljubljana': [46.06, 14.51, 'SI'], 'Europe/Vilnius': [54.69, 25.28, 'LT'],
  'Europe/Riga': [56.95, 24.11, 'LV'], 'Europe/Tallinn': [59.44, 24.75, 'EE'],
  'Atlantic/Reykjavik': [64.15, -21.94, 'IS'], 'Atlantic/Canary': [28.12, -15.44, 'ES'],

  // North America
  'America/New_York': [40.71, -74.01, 'US'], 'America/Toronto': [43.65, -79.38, 'CA'],
  'America/Montreal': [45.50, -73.57, 'CA'], 'America/Detroit': [42.33, -83.05, 'US'],
  'America/Chicago': [41.88, -87.63, 'US'], 'America/Winnipeg': [49.90, -97.14, 'CA'],
  'America/Mexico_City': [19.43, -99.13, 'MX'], 'America/Denver': [39.74, -104.99, 'US'],
  'America/Phoenix': [33.45, -112.07, 'US'], 'America/Edmonton': [53.55, -113.49, 'CA'],
  'America/Los_Angeles': [34.05, -118.24, 'US'], 'America/Vancouver': [49.28, -123.12, 'CA'],
  'America/Anchorage': [61.22, -149.90, 'US'], 'Pacific/Honolulu': [21.31, -157.86, 'US'],
  'America/Halifax': [44.65, -63.58, 'CA'], 'America/St_Johns': [47.56, -52.71, 'CA'],

  // South and Central America
  'America/Sao_Paulo': [-23.55, -46.63, 'BR'], 'America/Argentina/Buenos_Aires': [-34.60, -58.38, 'AR'],
  'America/Santiago': [-33.45, -70.67, 'CL'], 'America/Lima': [-12.05, -77.04, 'PE'],
  'America/Bogota': [4.71, -74.07, 'CO'], 'America/Caracas': [10.49, -66.88, 'VE'],
  'America/Panama': [8.98, -79.52, 'PA'], 'America/Havana': [23.11, -82.37, 'CU'],
  'America/Guatemala': [14.63, -90.51, 'GT'], 'America/Montevideo': [-34.90, -56.16, 'UY'],

  // Africa and the Middle East
  'Africa/Casablanca': [33.57, -7.59, 'MA'], 'Africa/Lagos': [6.52, 3.38, 'NG'],
  'Africa/Accra': [5.60, -0.19, 'GH'], 'Africa/Algiers': [36.75, 3.06, 'DZ'],
  'Africa/Tunis': [36.81, 10.18, 'TN'], 'Africa/Cairo': [30.04, 31.24, 'EG'],
  'Africa/Nairobi': [-1.29, 36.82, 'KE'], 'Africa/Addis_Ababa': [9.03, 38.74, 'ET'],
  'Africa/Johannesburg': [-26.20, 28.05, 'ZA'], 'Africa/Kinshasa': [-4.44, 15.27, 'CD'],
  'Asia/Jerusalem': [31.77, 35.21, 'IL'], 'Asia/Beirut': [33.89, 35.50, 'LB'],
  'Asia/Riyadh': [24.71, 46.68, 'SA'], 'Asia/Dubai': [25.20, 55.27, 'AE'],
  'Asia/Qatar': [25.29, 51.53, 'QA'], 'Asia/Kuwait': [29.38, 47.99, 'KW'],
  'Asia/Baghdad': [33.31, 44.37, 'IQ'], 'Asia/Tehran': [35.69, 51.39, 'IR'],

  // Asia
  'Asia/Karachi': [24.86, 67.01, 'PK'], 'Asia/Kolkata': [22.57, 88.36, 'IN'],
  'Asia/Calcutta': [22.57, 88.36, 'IN'], 'Asia/Colombo': [6.93, 79.86, 'LK'],
  'Asia/Kathmandu': [27.72, 85.32, 'NP'], 'Asia/Dhaka': [23.81, 90.41, 'BD'],
  'Asia/Yangon': [16.87, 96.20, 'MM'], 'Asia/Bangkok': [13.76, 100.50, 'TH'],
  'Asia/Ho_Chi_Minh': [10.82, 106.63, 'VN'], 'Asia/Jakarta': [-6.21, 106.85, 'ID'],
  'Asia/Singapore': [1.35, 103.82, 'SG'], 'Asia/Kuala_Lumpur': [3.14, 101.69, 'MY'],
  'Asia/Manila': [14.60, 120.98, 'PH'], 'Asia/Hong_Kong': [22.32, 114.17, 'HK'],
  'Asia/Taipei': [25.03, 121.57, 'TW'], 'Asia/Shanghai': [31.23, 121.47, 'CN'],
  'Asia/Chongqing': [29.56, 106.55, 'CN'], 'Asia/Seoul': [37.57, 126.98, 'KR'],
  'Asia/Tokyo': [35.68, 139.69, 'JP'], 'Asia/Almaty': [43.24, 76.89, 'KZ'],
  'Asia/Tashkent': [41.30, 69.24, 'UZ'], 'Asia/Baku': [40.41, 49.87, 'AZ'],
  'Asia/Tbilisi': [41.72, 44.79, 'GE'], 'Asia/Yerevan': [40.18, 44.51, 'AM'],
  'Asia/Novosibirsk': [55.01, 82.94, 'RU'], 'Asia/Vladivostok': [43.12, 131.89, 'RU'],

  // Oceania
  'Australia/Perth': [-31.95, 115.86, 'AU'], 'Australia/Adelaide': [-34.93, 138.60, 'AU'],
  'Australia/Darwin': [-12.46, 130.84, 'AU'], 'Australia/Brisbane': [-27.47, 153.03, 'AU'],
  'Australia/Sydney': [-33.87, 151.21, 'AU'], 'Australia/Melbourne': [-37.81, 144.96, 'AU'],
  'Australia/Hobart': [-42.88, 147.33, 'AU'], 'Pacific/Auckland': [-36.85, 174.76, 'NZ'],
  'Pacific/Fiji': [-18.14, 178.44, 'FJ'], 'Pacific/Guam': [13.44, 144.79, 'GU'],

  UTC: [0, 0, null], GMT: [0, 0, null],
};

// Everything that isn't a place: a location that can't be placed is no location at all.
function fromTimezone(zone) {
  if (typeof zone !== 'string') return null;
  const found = ZONES[zone];
  if (!found) return null;
  const [latitude, longitude, country] = found;
  return { latitude, longitude, country, source: 'timezone', zone };
}

// The seam for a real GeoIP database. Returning null means "no idea", and callers fall back to
// the time zone the browser reported.
let lookupIp = () => null;
const setIpLookup = (fn) => { lookupIp = typeof fn === 'function' ? fn : () => null; };

// Best available location for a sign-in. A GeoIP hit wins, because it describes where the
// traffic actually came from; the browser's time zone is the fallback.
function locate({ ip = null, timezone = null } = {}) {
  const fromIp = ip ? lookupIp(ip) : null;
  if (fromIp && Number.isFinite(fromIp.latitude) && Number.isFinite(fromIp.longitude)) {
    return { ...fromIp, source: 'ip' };
  }
  return fromTimezone(timezone);
}

const toRadians = (degrees) => (degrees * Math.PI) / 180;

// Great-circle distance in kilometres.
function distanceKm(a, b) {
  if (!a || !b) return null;
  const dLat = toRadians(b.latitude - a.latitude);
  const dLon = toRadians(b.longitude - a.longitude);
  const h = Math.sin(dLat / 2) ** 2
    + Math.cos(toRadians(a.latitude)) * Math.cos(toRadians(b.latitude)) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

// How fast someone would have had to move between two sign-ins, and whether that is possible.
//
// Two sign-ins in the same second from different places give an infinite speed, which is
// correct: they are simultaneous, and one of them is not where it claims to be.
function travelBetween(a, b) {
  const km = distanceKm(a.location, b.location);
  if (km === null) return null;

  const hours = Math.abs(b.at - a.at) / 3_600_000;
  const speed = hours > 0 ? km / hours : Infinity;
  return {
    distanceKm: Math.round(km),
    hours: Number(hours.toFixed(3)),
    speedKmh: Number.isFinite(speed) ? Math.round(speed) : Infinity,
    impossible: km >= MIN_DISTANCE_KM && speed > MAX_SPEED_KMH,
  };
}

module.exports = {
  ZONES, MAX_SPEED_KMH, MIN_DISTANCE_KM,
  fromTimezone, locate, setIpLookup, distanceKm, travelBetween,
};
