import ReportView from "@/components/views/ReportView";

export function generateStaticParams() {
  return [{ id: "demo" }, { id: "latest" }, { id: "sample" }];
}

export default function Page() {
  return <ReportView />;
}
