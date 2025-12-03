import multer from "multer";

const storage = multer.memoryStorage();

export const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "text/csv") cb(null, true);
    else cb(new Error("Only CSV files are allowed"), false);
  }
});
