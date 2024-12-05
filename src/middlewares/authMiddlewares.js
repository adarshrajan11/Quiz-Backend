import jwt from "jsonwebtoken";
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    console.error("No token provided");
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded token:", decoded); // Log decoded token
    req.user = decoded; // Attach decoded payload to the request object
    next(); // Proceed to the next middleware/route
  } catch (err) {
    console.error("Token verification error:", err.message); // Log error
    return res.status(403).json({ message: "Invalid token." });
  }
};
export default authenticate;
