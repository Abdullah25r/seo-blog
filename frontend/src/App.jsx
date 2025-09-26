import React from "react";
import { Routes, Route } from "react-router-dom";
import Home from "./Pages/Home";
import BlogPost from "./Pages/BlogPost";
import CategoryPage from "./Pages/CategoryPage";
import AdminDashboard from "./Pages/AdminDashboard";
import AdminLogin from "./components/Admin/AdminLogin";
import ProtectedRoute from "./components/ProtectRoute";
const App = () => {
  return (
    <div className="min-h-screen">
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/category/:categorySlug" element={<CategoryPage />} />
        <Route
          path="/category/:categorySlug/:postSlug"
          element={<BlogPost />}
        />

        <Route path="/admin" element={<AdminLogin />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <AdminDashboard />
            </ProtectedRoute>
          }
        />
      </Routes>
    </div>
  );
};

export default App;
